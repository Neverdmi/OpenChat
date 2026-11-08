//! `oc-desktop` — OpenChat desktop UI (egui).
//!
//! Run without arguments for the graphical interface. Pass `--cli`
//! anywhere before the subcommand to run the exact same command-line
//! interface as the `oc` binary instead, e.g.
//! `oc-desktop --cli chat <peer>`.

mod app;

use std::ffi::OsString;

use eframe::egui;
use std::time::Duration;

use app::{OpenChatApp, WorkerCommand};

/// Whether the given argv requests CLI mode (`--cli` present).
fn is_cli_mode(argv: &[OsString]) -> bool {
    argv.iter().any(|arg| arg == "--cli")
}

/// Build the argv for the CLI entry point: drop `--cli`, keep the rest.
fn cli_args_from(argv: &[OsString]) -> Vec<OsString> {
    let mut args = vec![OsString::from("oc")];
    args.extend(
        argv.iter()
            .skip(1)
            .filter(|arg| *arg != "--cli")
            .cloned(),
    );
    args
}

fn main() {
    let argv: Vec<OsString> = std::env::args_os().collect();
    if is_cli_mode(&argv) {
        if let Err(error) = oc_cli::run_cli_from(cli_args_from(&argv)) {
            eprintln!("error: {error:#}");
            std::process::exit(1);
        }
        return;
    }

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([960.0, 640.0]),
        ..Default::default()
    };
    if let Err(error) = eframe::run_native(
        "OpenChat",
        options,
        Box::new(|_cc| Ok(Box::new(OpenChatApp::new()))),
    ) {
        eprintln!("desktop error: {error}");
        std::process::exit(1);
    }
}

impl eframe::App for OpenChatApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_events();

        if self.is_locked() {
            self.unlock_screen(ctx);
            return;
        }

        ctx.request_repaint_after(Duration::from_millis(250));

        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("OpenChat");
                ui.label(format!("outbox: {}", self.outbox_len));
                if ui.button("Retry queue").clicked() {
                    if let Some(worker) = &self.worker {
                        let _ = worker.commands.send(WorkerCommand::Flush);
                    }
                }
                ui.label(&self.status);
            });
            if let Some(error) = &self.error {
                ui.colored_label(egui::Color32::RED, error);
            }
            ui.horizontal(|ui| {
                ui.label("invite:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.invite)
                        .hint_text("your invite link")
                        .desired_width(f32::INFINITY),
                );
            });
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.invite_input)
                        .hint_text("paste invite link to add a contact")
                        .desired_width(f32::INFINITY),
                );
                if ui.button("Add contact").clicked() {
                    let link = self.invite_input.trim().to_string();
                    if !link.is_empty() {
                        if let Some(worker) = &self.worker {
                            let _ = worker
                                .commands
                                .send(WorkerCommand::AddInvite(link));
                        }
                        self.invite_input.clear();
                    }
                }
            });
        });

        egui::SidePanel::left("contacts").show(ctx, |ui| {
            ui.heading("Contacts");
            for contact in self.contacts.clone() {
                let marker = if contact.verified { "✓" } else { "?" };
                let label = format!("{} {}", contact.short, marker);
                let selected = self.selected == Some(contact.peer_id);
                if ui.selectable_label(selected, label).clicked() {
                    self.selected = Some(contact.peer_id);
                }
                if selected {
                    ui.label(format!("safety: {}", contact.safety));
                }
            }
            if self.contacts.is_empty() {
                ui.label("no contacts yet — add one with an invite above");
            }
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            let title = match self.selected_short() {
                Some(short) => format!("Chat with {short}"),
                None => "No contact selected".to_string(),
            };
            ui.heading(title);

            egui::ScrollArea::vertical()
                .auto_shrink([false; 2])
                .show(ui, |ui| {
                    for line in self.lines.clone() {
                        let text = format!("{}: {}", line.author, line.text);
                        if line.outgoing {
                            ui.colored_label(egui::Color32::LIGHT_GRAY, text);
                        } else {
                            ui.label(text);
                        }
                    }
                });

            ui.horizontal(|ui| {
                let input = egui::TextEdit::singleline(&mut self.input)
                    .hint_text("message (text only)")
                    .desired_width(f32::INFINITY);
                let response = ui.add(input);
                let enter = ctx.input(|state| state.key_pressed(egui::Key::Enter));
                let send_clicked = ui
                    .add_enabled(self.can_send(), egui::Button::new("Send"))
                    .clicked();
                if send_clicked || (enter && response.lost_focus() && self.can_send()) {
                    self.queue_send();
                }
            });
            ui.label("Text only. History is not stored — messages live for this session.");
        });
    }
}

impl OpenChatApp {
    fn unlock_screen(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("OpenChat");
            ui.label("Unlock your encrypted state to start chatting.");
            ui.add(
                egui::TextEdit::singleline(&mut self.home)
                    .hint_text("state directory (~/.openchat)"),
            );
            let passphrase = egui::TextEdit::singleline(&mut self.passphrase)
                .password(true)
                .hint_text("passphrase");
            let response = ui.add(passphrase);
            let enter = ctx.input(|state| state.key_pressed(egui::Key::Enter));
            let unlock_clicked = ui.button("Unlock").clicked();
            if unlock_clicked || (enter && response.lost_focus() && !self.passphrase.is_empty()) {
                self.unlock();
            }
            if let Some(error) = &self.error {
                ui.colored_label(egui::Color32::RED, error);
            }
            ui.label("No state yet? Create one first with: oc init --relay <url>");
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(items: &[&str]) -> Vec<OsString> {
        items.iter().map(OsString::from).collect()
    }

    #[test]
    fn cli_mode_detection() {
        assert!(is_cli_mode(&argv(&["oc-desktop", "--cli"])));
        assert!(is_cli_mode(&argv(&["oc-desktop", "--cli", "chat"])));
        assert!(!is_cli_mode(&argv(&["oc-desktop"])));
        assert!(!is_cli_mode(&argv(&["oc-desktop", "chat"])));
    }

    #[test]
    fn cli_args_strip_flag_and_keep_subcommand() {
        assert_eq!(
            cli_args_from(&argv(&["oc-desktop", "--cli", "chat", "ABCD"])),
            argv(&["oc", "chat", "ABCD"])
        );
        assert_eq!(
            cli_args_from(&argv(&["oc-desktop", "--cli", "--help"])),
            argv(&["oc", "--help"])
        );
        assert_eq!(cli_args_from(&argv(&["oc-desktop"])), argv(&["oc"]));
    }
}
