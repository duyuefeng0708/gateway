use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use gateway_anonymizer::detector::PiiDetector;
use gateway_anonymizer::placeholder;
use gateway_anonymizer::regex_detector::RegexDetector;
use gateway_common::types::PrivacyScore;
use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    Terminal,
};
use std::io::{self, stdout};

/// Application state for the demo TUI.
struct App {
    /// Text the user is currently typing.
    input: String,
    /// The original prompt text (set on Enter).
    original: String,
    /// The anonymized prompt text (set on Enter).
    anonymized: String,
    /// Privacy score from the last analysis.
    privacy_score: u32,
    /// Number of PII items detected in the last analysis.
    pii_count: usize,
    /// Whether the app should exit.
    should_quit: bool,
    /// The regex detector instance.
    detector: RegexDetector,
}

impl App {
    fn new() -> Self {
        Self {
            input: String::new(),
            original: String::new(),
            anonymized: String::new(),
            privacy_score: 100,
            pii_count: 0,
            should_quit: false,
            detector: RegexDetector::new(),
        }
    }

    /// Analyze the current input through the PII pipeline.
    async fn analyze(&mut self) {
        let text = self.input.clone();
        self.original = text.clone();

        match self.detector.detect(&text).await {
            Ok(spans) => {
                let score = PrivacyScore::compute(&spans);
                self.privacy_score = score.value();
                self.pii_count = spans.len();

                let (redacted, _placeholders) = placeholder::substitute(&text, &spans);
                self.anonymized = redacted;
            }
            Err(_) => {
                // RegexDetector should never fail, but handle gracefully
                self.anonymized = text;
                self.privacy_score = 100;
                self.pii_count = 0;
            }
        }

        self.input.clear();
    }
}

/// Run the interactive demo TUI.
pub async fn run() -> io::Result<()> {
    // Set up terminal
    enable_raw_mode()?;
    stdout().execute(EnterAlternateScreen)?;
    let backend = ratatui::backend::CrosstermBackend::new(stdout());
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new();

    // Main event loop
    loop {
        terminal.draw(|frame| draw(frame, &app))?;

        if event::poll(std::time::Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                // Only handle key press events (not release/repeat)
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match key.code {
                    KeyCode::Esc => {
                        app.should_quit = true;
                    }
                    KeyCode::Char('q') if app.input.is_empty() => {
                        app.should_quit = true;
                    }
                    KeyCode::Char(c) => {
                        app.input.push(c);
                    }
                    KeyCode::Backspace => {
                        app.input.pop();
                    }
                    KeyCode::Enter => {
                        if !app.input.is_empty() {
                            app.analyze().await;
                        }
                    }
                    _ => {}
                }
            }
        }

        if app.should_quit {
            break;
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    stdout().execute(LeaveAlternateScreen)?;

    Ok(())
}

/// Draw the TUI layout.
fn draw(frame: &mut ratatui::Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(5),    // Main panes area
            Constraint::Length(3), // Status bar + input
        ])
        .split(frame.area());

    // Split main area into two side-by-side panes
    let panes = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[0]);

    // Left pane: Original Prompt
    let original_block = Block::default()
        .title(" Original Prompt ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));

    let original_text = if app.original.is_empty() {
        Paragraph::new("Type a prompt below and press Enter...")
            .style(Style::default().fg(Color::DarkGray))
            .block(original_block)
            .wrap(Wrap { trim: false })
    } else {
        Paragraph::new(app.original.as_str())
            .style(Style::default().fg(Color::White))
            .block(original_block)
            .wrap(Wrap { trim: false })
    };
    frame.render_widget(original_text, panes[0]);

    // Right pane: Anonymized Prompt
    let anonymized_block = Block::default()
        .title(" Anonymized Prompt ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Green));

    let anonymized_text = if app.anonymized.is_empty() {
        Paragraph::new("Anonymized output will appear here...")
            .style(Style::default().fg(Color::DarkGray))
            .block(anonymized_block)
            .wrap(Wrap { trim: false })
    } else {
        Paragraph::new(app.anonymized.as_str())
            .style(Style::default().fg(Color::White))
            .block(anonymized_block)
            .wrap(Wrap { trim: false })
    };
    frame.render_widget(anonymized_text, panes[1]);

    // Bottom bar: status + input
    let bottom_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Length(2)])
        .split(chunks[1]);

    // Status line
    let score_color = match app.privacy_score {
        90..=100 => Color::Green,
        50..=89 => Color::Yellow,
        _ => Color::Red,
    };

    let status_line = Line::from(vec![
        Span::raw(" Privacy Score: "),
        Span::styled(
            format!("{}/100", app.privacy_score),
            Style::default()
                .fg(score_color)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" | "),
        Span::styled(
            format!("{} PII item{} detected", app.pii_count, if app.pii_count == 1 { "" } else { "s" }),
            Style::default().fg(Color::White),
        ),
        Span::raw(" | "),
        Span::styled(
            "Press q or Esc to quit",
            Style::default().fg(Color::DarkGray),
        ),
    ]);

    let status = Paragraph::new(status_line)
        .style(Style::default().bg(Color::DarkGray).fg(Color::White));
    frame.render_widget(status, bottom_chunks[0]);

    // Input line
    let input_display = format!(" > {}_", app.input);
    let input = Paragraph::new(input_display)
        .style(Style::default().fg(Color::Cyan));
    frame.render_widget(input, bottom_chunks[1]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_initializes_with_defaults() {
        let app = App::new();
        assert!(app.input.is_empty());
        assert!(app.original.is_empty());
        assert!(app.anonymized.is_empty());
        assert_eq!(app.privacy_score, 100);
        assert_eq!(app.pii_count, 0);
        assert!(!app.should_quit);
    }

    #[tokio::test]
    async fn analyze_detects_email() {
        let mut app = App::new();
        app.input = "Contact john@example.com about the project.".to_string();
        app.analyze().await;

        assert_eq!(app.original, "Contact john@example.com about the project.");
        assert!(!app.anonymized.contains("john@example.com"));
        assert!(app.anonymized.contains("[EMAIL_"));
        assert_eq!(app.pii_count, 1);
        assert!(app.privacy_score < 100);
        assert!(app.input.is_empty()); // input cleared after analyze
    }

    #[tokio::test]
    async fn analyze_no_pii() {
        let mut app = App::new();
        app.input = "The weather in Paris is nice.".to_string();
        app.analyze().await;

        assert_eq!(app.original, "The weather in Paris is nice.");
        assert_eq!(app.anonymized, "The weather in Paris is nice.");
        assert_eq!(app.pii_count, 0);
        assert_eq!(app.privacy_score, 100);
    }

    #[tokio::test]
    async fn analyze_multiple_pii_types() {
        let mut app = App::new();
        app.input = "Email alice@test.com, SSN 123-45-6789".to_string();
        app.analyze().await;

        assert!(!app.anonymized.contains("alice@test.com"));
        assert!(!app.anonymized.contains("123-45-6789"));
        assert!(app.pii_count >= 2);
        assert!(app.privacy_score < 100);
    }

    #[tokio::test]
    async fn analyze_clears_input() {
        let mut app = App::new();
        app.input = "test@example.com".to_string();
        app.analyze().await;
        assert!(app.input.is_empty());
    }
}
