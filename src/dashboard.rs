use anyhow::{anyhow, Result};
use std::io::{self, Write};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};
use crossterm::{
    ExecutableCommand, QueueableCommand,
    cursor, terminal, style::{self, Color as CrosstermColor, Stylize},
    event::{self, Event, KeyCode, KeyEvent},
};
use tui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Style, Modifier, Color},
    symbols,
    text::{Span, Spans},
    widgets::{Block, Borders, Paragraph, Tabs, List, ListItem, Gauge, Chart, Dataset, Axis, BarChart},
    Terminal,
};

use crate::telemetry::SecurityEvent;
use crate::resources::ResourceMetrics;
use crate::security::BreachEvent;

/// Dashboard state
#[derive(Debug, Clone)]
pub struct DashboardState {
    /// Current tab index
    pub tab_index: usize,
    /// Resource metrics history
    pub resource_metrics: Vec<ResourceMetrics>,
    /// Security events
    pub security_events: Vec<SecurityEvent>,
    /// Breach events
    pub breach_events: Vec<BreachEvent>,
    /// Process start time
    pub start_time: Instant,
    /// Active process IDs being monitored
    pub active_pids: Vec<u32>,
    /// Currently selected process ID
    pub selected_pid: Option<u32>,
    /// Whether to auto-refresh
    pub auto_refresh: bool,
    /// Auto-refresh interval
    pub refresh_interval: Duration,
    /// Whether the dashboard is running
    pub running: bool,
}

impl Default for DashboardState {
    fn default() -> Self {
        Self {
            tab_index: 0,
            resource_metrics: Vec::new(),
            security_events: Vec::new(),
            breach_events: Vec::new(),
            start_time: Instant::now(),
            active_pids: Vec::new(),
            selected_pid: None,
            auto_refresh: true,
            refresh_interval: Duration::from_secs(1),
            running: false,
        }
    }
}

/// Dashboard for monitoring sandboxed processes
pub struct Dashboard {
    /// Dashboard state
    state: Arc<Mutex<DashboardState>>,
    /// Terminal for UI rendering
    terminal: Option<Terminal<CrosstermBackend<io::Stdout>>>,
    /// Event channel
    event_tx: mpsc::Sender<DashboardEvent>,
    event_rx: mpsc::Receiver<DashboardEvent>,
}

/// Dashboard event
#[derive(Debug, Clone)]
pub enum DashboardEvent {
    /// New resource metrics
    ResourceMetrics(ResourceMetrics),
    /// New security event
    SecurityEvent(SecurityEvent),
    /// New breach event
    BreachEvent(BreachEvent),
    /// Process started
    ProcessStarted(u32),
    /// Process terminated
    ProcessTerminated(u32),
    /// Refresh request
    Refresh,
    /// Quit request
    Quit,
}

impl Dashboard {
    /// Create a new dashboard
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel();
        
        Self {
            state: Arc::new(Mutex::new(DashboardState::default())),
            terminal: None,
            event_tx: tx,
            event_rx: rx,
        }
    }
    
    /// Get an event sender to send events to the dashboard
    pub fn get_event_sender(&self) -> mpsc::Sender<DashboardEvent> {
        self.event_tx.clone()
    }
    
    /// Initialize the dashboard
    pub fn init(&mut self) -> Result<()> {
        // Enter alternate screen
        io::stdout().execute(terminal::EnterAlternateScreen)?;
        terminal::enable_raw_mode()?;
        
        // Create terminal
        let backend = CrosstermBackend::new(io::stdout());
        self.terminal = Some(Terminal::new(backend)?);
        
        // Update state
        {
            let mut state = self.state.lock().unwrap();
            state.running = true;
        }
        
        Ok(())
    }
    
    /// Run the dashboard until quit
    pub fn run(&mut self) -> Result<()> {
        if self.terminal.is_none() {
            self.init()?;
        }
        
        let state_clone = Arc::clone(&self.state);
        let event_tx = self.event_tx.clone();
        
        // Spawn input thread
        thread::spawn(move || {
            let mut last_tick = Instant::now();
            
            loop {
                let state = state_clone.lock().unwrap();
                if !state.running {
                    break;
                }
                
                let refresh_interval = state.refresh_interval;
                let auto_refresh = state.auto_refresh;
                drop(state);
                
                // Poll for events with timeout
                if event::poll(Duration::from_millis(100)).unwrap() {
                    if let Event::Key(key) = event::read().unwrap() {
                        Self::handle_key_event(key, &event_tx, &state_clone);
                    }
                }
                
                // Auto-refresh if enabled
                if auto_refresh && last_tick.elapsed() >= refresh_interval {
                    let _ = event_tx.send(DashboardEvent::Refresh);
                    last_tick = Instant::now();
                }
            }
        });
        
        // Main loop
        while let Ok(event) = self.event_rx.recv() {
            match event {
                DashboardEvent::Quit => {
                    let mut state = self.state.lock().unwrap();
                    state.running = false;
                    break;
                },
                DashboardEvent::ResourceMetrics(metrics) => {
                    let mut state = self.state.lock().unwrap();
                    state.resource_metrics.push(metrics);
                    // Keep only the last 60 metrics (for history)
                    if state.resource_metrics.len() > 60 {
                        state.resource_metrics.remove(0);
                    }
                },
                DashboardEvent::SecurityEvent(event) => {
                    let mut state = self.state.lock().unwrap();
                    state.security_events.push(event);
                },
                DashboardEvent::BreachEvent(event) => {
                    let mut state = self.state.lock().unwrap();
                    state.breach_events.push(event);
                },
                DashboardEvent::ProcessStarted(pid) => {
                    let mut state = self.state.lock().unwrap();
                    if !state.active_pids.contains(&pid) {
                        state.active_pids.push(pid);
                    }
                    if state.selected_pid.is_none() {
                        state.selected_pid = Some(pid);
                    }
                },
                DashboardEvent::ProcessTerminated(pid) => {
                    let mut state = self.state.lock().unwrap();
                    state.active_pids.retain(|&p| p != pid);
                    if state.selected_pid == Some(pid) {
                        state.selected_pid = state.active_pids.first().cloned();
                    }
                },
                DashboardEvent::Refresh => {
                    // Just trigger a redraw
                },
            }
            
            // Render the UI
            if let Some(terminal) = &mut self.terminal {
                terminal.draw(|f| {
                    let state = self.state.lock().unwrap();
                    Self::render(&state, f);
                })?;
            }
        }
        
        self.cleanup()?;
        Ok(())
    }
    
    /// Cleanup on exit
    pub fn cleanup(&mut self) -> Result<()> {
        // Disable raw mode
        terminal::disable_raw_mode()?;
        
        // Leave alternate screen
        if let Some(terminal) = &mut self.terminal {
            terminal.backend_mut().execute(terminal::LeaveAlternateScreen)?;
        }
        
        Ok(())
    }
    
    /// Handle key events
    fn handle_key_event(key: KeyEvent, tx: &mpsc::Sender<DashboardEvent>, state: &Arc<Mutex<DashboardState>>) {
        match key.code {
            KeyCode::Char('q') => {
                let _ = tx.send(DashboardEvent::Quit);
            },
            KeyCode::Char('r') => {
                let _ = tx.send(DashboardEvent::Refresh);
            },
            KeyCode::Char('a') => {
                let mut state = state.lock().unwrap();
                state.auto_refresh = !state.auto_refresh;
            },
            KeyCode::Tab => {
                let mut state = state.lock().unwrap();
                state.tab_index = (state.tab_index + 1) % 3;
            },
            KeyCode::BackTab => {
                let mut state = state.lock().unwrap();
                state.tab_index = if state.tab_index == 0 { 2 } else { state.tab_index - 1 };
            },
            KeyCode::Up => {
                let mut state = state.lock().unwrap();
                if !state.active_pids.is_empty() {
                    let current_idx = state.active_pids.iter().position(|&p| Some(p) == state.selected_pid);
                    if let Some(idx) = current_idx {
                        let prev_idx = if idx == 0 { state.active_pids.len() - 1 } else { idx - 1 };
                        state.selected_pid = Some(state.active_pids[prev_idx]);
                    } else {
                        state.selected_pid = Some(state.active_pids[0]);
                    }
                }
            },
            KeyCode::Down => {
                let mut state = state.lock().unwrap();
                if !state.active_pids.is_empty() {
                    let current_idx = state.active_pids.iter().position(|&p| Some(p) == state.selected_pid);
                    if let Some(idx) = current_idx {
                        let next_idx = (idx + 1) % state.active_pids.len();
                        state.selected_pid = Some(state.active_pids[next_idx]);
                    } else {
                        state.selected_pid = Some(state.active_pids[0]);
                    }
                }
            },
            _ => {},
        }
    }
    
    /// Render the dashboard
    fn render(state: &DashboardState, frame: &mut tui::Frame<CrosstermBackend<io::Stdout>>) {
        let size = frame.size();
        
        // Create main layout
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(2)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(0),
            ].as_ref())
            .split(size);
        
        // Render tabs
        let titles = vec!["Resources", "Security", "Events"];
        let tabs = Tabs::new(titles.iter().map(|t| Spans::from(Span::styled(*t, Style::default().fg(Color::Green)))).collect())
            .select(state.tab_index)
            .block(Block::default().borders(Borders::ALL).title("Rusty Sandbox Monitor"))
            .highlight_style(Style::default().fg(Color::Yellow))
            .divider(Span::raw("|"));
        
        frame.render_widget(tabs, chunks[0]);
        
        // Render content based on selected tab
        match state.tab_index {
            0 => Self::render_resources_tab(state, frame, chunks[1]),
            1 => Self::render_security_tab(state, frame, chunks[1]),
            2 => Self::render_events_tab(state, frame, chunks[1]),
            _ => {},
        }
    }
    
    /// Render the resources tab
    fn render_resources_tab(state: &DashboardState, frame: &mut tui::Frame<CrosstermBackend<io::Stdout>>, area: Rect) {
        let layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Percentage(30),
                Constraint::Percentage(30),
                Constraint::Percentage(40),
            ].as_ref())
            .split(area);
        
        // CPU usage chart
        let cpu_data: Vec<(f64, f64)> = state.resource_metrics.iter()
            .enumerate()
            .filter_map(|(i, m)| {
                m.cpu_usage.map(|usage| (i as f64, usage))
            })
            .collect();
        
        let datasets = vec![
            Dataset::default()
                .name("CPU Usage %")
                .marker(symbols::Marker::Braille)
                .style(Style::default().fg(Color::Cyan))
                .data(&cpu_data),
        ];
        
        let cpu_chart = Chart::new(datasets)
            .block(Block::default().title("CPU Usage").borders(Borders::ALL))
            .x_axis(Axis::default()
                .title(Span::styled("Time", Style::default().fg(Color::White)))
                .style(Style::default().fg(Color::White))
                .bounds([0.0, 60.0]))
            .y_axis(Axis::default()
                .title(Span::styled("Usage %", Style::default().fg(Color::White)))
                .style(Style::default().fg(Color::White))
                .bounds([0.0, 100.0]));
        
        frame.render_widget(cpu_chart, layout[0]);
        
        // Memory usage chart
        let mem_data: Vec<(f64, f64)> = state.resource_metrics.iter()
            .enumerate()
            .filter_map(|(i, m)| {
                m.memory_usage_percent.map(|usage| (i as f64, usage))
            })
            .collect();
        
        let datasets = vec![
            Dataset::default()
                .name("Memory Usage %")
                .marker(symbols::Marker::Braille)
                .style(Style::default().fg(Color::Magenta))
                .data(&mem_data),
        ];
        
        let mem_chart = Chart::new(datasets)
            .block(Block::default().title("Memory Usage").borders(Borders::ALL))
            .x_axis(Axis::default()
                .title(Span::styled("Time", Style::default().fg(Color::White)))
                .style(Style::default().fg(Color::White))
                .bounds([0.0, 60.0]))
            .y_axis(Axis::default()
                .title(Span::styled("Usage %", Style::default().fg(Color::White)))
                .style(Style::default().fg(Color::White))
                .bounds([0.0, 100.0]));
        
        frame.render_widget(mem_chart, layout[1]);
        
        // Process details
        let details_layout = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(30),
                Constraint::Percentage(70),
            ].as_ref())
            .split(layout[2]);
        
        // Process list
        let process_items: Vec<ListItem> = state.active_pids.iter()
            .map(|&pid| {
                let style = if Some(pid) == state.selected_pid {
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };
                
                ListItem::new(Spans::from(vec![
                    Span::styled(format!("PID: {}", pid), style),
                ]))
            })
            .collect();
        
        let process_list = List::new(process_items)
            .block(Block::default().title("Processes").borders(Borders::ALL))
            .highlight_style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD));
        
        frame.render_widget(process_list, details_layout[0]);
        
        // Process details
        let selected_pid = state.selected_pid.unwrap_or(0);
        let latest_metrics = state.resource_metrics.last();
        
        let details = if let Some(metrics) = latest_metrics {
            vec![
                Spans::from(Span::raw(format!("PID: {}", selected_pid))),
                Spans::from(Span::raw("")),
                Spans::from(Span::raw(format!("CPU: {:.2}%", metrics.cpu_usage.unwrap_or(0.0)))),
                Spans::from(Span::raw(format!("Memory: {:.2}MB", 
                                            metrics.memory_usage_bytes.unwrap_or(0) as f64 / 1024.0 / 1024.0))),
                Spans::from(Span::raw(format!("Threads: {}", metrics.thread_count.unwrap_or(0)))),
                Spans::from(Span::raw(format!("Open Files: {}", metrics.open_files.unwrap_or(0)))),
                Spans::from(Span::raw("")),
                Spans::from(Span::styled(
                    format!("Status: {}", if metrics.limits_exceeded { "LIMITS EXCEEDED" } else { "OK" }),
                    if metrics.limits_exceeded { Style::default().fg(Color::Red) } else { Style::default().fg(Color::Green) }
                )),
            ]
        } else {
            vec![
                Spans::from(Span::raw("No metrics available")),
            ]
        };
        
        let details_widget = Paragraph::new(details)
            .block(Block::default().title("Process Details").borders(Borders::ALL));
        
        frame.render_widget(details_widget, details_layout[1]);
    }
    
    /// Render the security tab
    fn render_security_tab(state: &DashboardState, frame: &mut tui::Frame<CrosstermBackend<io::Stdout>>, area: Rect) {
        let layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Percentage(60),
                Constraint::Percentage(40),
            ].as_ref())
            .split(area);
        
        // Breach events
        let breach_items: Vec<ListItem> = state.breach_events.iter()
            .map(|event| {
                let severity_style = match event.severity {
                    crate::security::SeverityLevel::Critical => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    crate::security::SeverityLevel::High => Style::default().fg(Color::Red),
                    crate::security::SeverityLevel::Medium => Style::default().fg(Color::Yellow),
                    crate::security::SeverityLevel::Low => Style::default().fg(Color::Blue),
                    crate::security::SeverityLevel::Info => Style::default().fg(Color::Green),
                };
                
                ListItem::new(Spans::from(vec![
                    Span::styled(
                        format!("[{}] ", event.breach_type),
                        severity_style
                    ),
                    Span::raw(event.description.clone()),
                ]))
            })
            .collect();
        
        let breach_list = List::new(breach_items)
            .block(Block::default().title("Security Breaches").borders(Borders::ALL));
        
        frame.render_widget(breach_list, layout[0]);
        
        // Security summary
        let file_violations = state.breach_events.iter()
            .filter(|e| e.breach_type == crate::security::BreachType::FileAccess)
            .count();
            
        let network_violations = state.breach_events.iter()
            .filter(|e| e.breach_type == crate::security::BreachType::Network)
            .count();
            
        let process_violations = state.breach_events.iter()
            .filter(|e| e.breach_type == crate::security::BreachType::Process)
            .count();
            
        let syscall_violations = state.breach_events.iter()
            .filter(|e| e.breach_type == crate::security::BreachType::Syscall)
            .count();
            
        let resource_violations = state.breach_events.iter()
            .filter(|e| e.breach_type == crate::security::BreachType::ResourceLimit)
            .count();
        
        let data = [
            ("File Access", file_violations as u64),
            ("Network", network_violations as u64),
            ("Process", process_violations as u64),
            ("Syscall", syscall_violations as u64),
            ("Resources", resource_violations as u64),
        ];
        
        let max_value = data.iter().map(|(_, v)| *v).max().unwrap_or(1);
        
        let barchart = BarChart::default()
            .block(Block::default().title("Security Violations").borders(Borders::ALL))
            .data(&data)
            .bar_width(9)
            .bar_style(Style::default().fg(Color::Red))
            .value_style(Style::default().fg(Color::White).add_modifier(Modifier::BOLD))
            .label_style(Style::default().fg(Color::White));
        
        frame.render_widget(barchart, layout[1]);
    }
    
    /// Render the events tab
    fn render_events_tab(state: &DashboardState, frame: &mut tui::Frame<CrosstermBackend<io::Stdout>>, area: Rect) {
        // Convert security events to list items
        let event_items: Vec<ListItem> = state.security_events.iter()
            .map(|event| {
                let style = match event.severity.as_str() {
                    "critical" => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    "error" => Style::default().fg(Color::Red),
                    "warning" => Style::default().fg(Color::Yellow),
                    _ => Style::default().fg(Color::White),
                };
                
                let pid_info = if let Some(pid) = event.process_id {
                    format!(" [PID: {}]", pid)
                } else {
                    String::new()
                };
                
                ListItem::new(Spans::from(vec![
                    Span::styled(
                        format!("[{}]", event.event_type),
                        style
                    ),
                    Span::raw(pid_info),
                    Span::raw(": "),
                    Span::raw(event.description.clone()),
                ]))
            })
            .collect();
        
        let events_list = List::new(event_items)
            .block(Block::default().title("Security Events").borders(Borders::ALL))
            .start_corner(tui::layout::Corner::TopLeft);
        
        frame.render_widget(events_list, area);
    }
} 