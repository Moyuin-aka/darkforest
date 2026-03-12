use std::{
    collections::{HashSet, VecDeque},
    io::{self, ErrorKind, Write},
    net::{SocketAddr, UdpSocket},
    sync::mpsc,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail, ensure};
use clap::{Args, Parser, Subcommand};
use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use rand::{Rng, rngs::OsRng};
use ratatui::{
    Frame, Terminal,
    layout::{Constraint, Direction, Layout},
    prelude::{Color, CrosstermBackend, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Paragraph, Wrap},
};
use socket2::{Domain, Protocol, Socket, Type};
use unicode_width::UnicodeWidthStr;

use darkforest::{
    BODY_LEN, LABEL_LEN, PACKET_LEN, PacketKind, PlainPacket, generate_key_hex, nonce_from_packet,
    open_packet, parse_key_hex, seal_packet,
};

const DEMO_SHARED_KEY_HEX: &str =
    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

#[derive(Parser, Debug)]
#[command(
    name = "darkforest",
    version,
    about = "宿舍内网黑暗森林通信原型：UDP 广播 + 加密 + 掩护流量"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    #[command(about = "生成一份 32 字节共享密钥")]
    GenKey,
    #[command(about = "发送一条加密广播消息")]
    Send(SendArgs),
    #[command(about = "监听并解密属于自己的广播消息")]
    Listen(ListenArgs),
    #[command(about = "进入终端聊天界面；参数不填时会启动前询问，回车可吃默认值")]
    Tui(TuiArgs),
}

#[derive(Args, Debug)]
struct SendArgs {
    #[arg(long, default_value = "0.0.0.0:0", help = "本地绑定地址")]
    bind: SocketAddr,
    #[arg(long, default_value = "255.255.255.255:9000", help = "广播目标地址")]
    broadcast: SocketAddr,
    #[arg(long, help = "64 位十六进制共享密钥")]
    key: String,
    #[arg(long, help = "发送者代号")]
    sender: String,
    #[arg(long, default_value = "all", help = "逻辑目标名，all 表示全体")]
    target: String,
    #[arg(long, help = "要发送的消息内容")]
    message: String,
}

#[derive(Args, Debug, Clone)]
struct SharedListenArgs {
    #[arg(long, default_value = "0.0.0.0:9000", help = "本地监听地址")]
    bind: SocketAddr,
    #[arg(
        long,
        default_value = "255.255.255.255:9000",
        help = "dummy 包广播地址"
    )]
    broadcast: SocketAddr,
    #[arg(long, help = "64 位十六进制共享密钥")]
    key: String,
    #[arg(long, help = "当前节点的名字")]
    name: String,
    #[arg(long, default_value_t = 1_500, help = "dummy 最短发送间隔，单位毫秒")]
    dummy_min_ms: u64,
    #[arg(long, default_value_t = 4_500, help = "dummy 最长发送间隔，单位毫秒")]
    dummy_max_ms: u64,
    #[arg(long, default_value_t = false, help = "关闭后台 dummy 掩护流量")]
    no_dummy: bool,
}

#[derive(Args, Debug)]
struct ListenArgs {
    #[command(flatten)]
    shared: SharedListenArgs,
    #[arg(long, default_value_t = false, help = "把 dummy 包也打印出来")]
    print_dummy: bool,
}

#[derive(Args, Debug, Clone)]
struct TuiArgs {
    #[arg(long, default_value = "0.0.0.0:9000", help = "本地监听地址")]
    bind: SocketAddr,
    #[arg(
        long,
        default_value = "255.255.255.255:9000",
        help = "dummy 包广播地址"
    )]
    broadcast: SocketAddr,
    #[arg(
        long,
        help = "64 位十六进制共享密钥；不填则启动前询问，回车使用课堂演示密钥"
    )]
    key: Option<String>,
    #[arg(long, help = "当前节点的名字；不填则启动前询问，回车使用默认代号")]
    name: Option<String>,
    #[arg(long, default_value_t = 1_500, help = "dummy 最短发送间隔，单位毫秒")]
    dummy_min_ms: u64,
    #[arg(long, default_value_t = 4_500, help = "dummy 最长发送间隔，单位毫秒")]
    dummy_max_ms: u64,
    #[arg(long, default_value_t = false, help = "关闭后台 dummy 掩护流量")]
    no_dummy: bool,
    #[arg(long, default_value = "all", help = "界面里的初始目标名")]
    target: String,
    #[arg(long, default_value_t = false, help = "在界面里显示 dummy 掩护包")]
    show_dummy: bool,
}

#[derive(Debug, Clone)]
struct RuntimeConfig {
    bind: SocketAddr,
    broadcast: SocketAddr,
    key: [u8; 32],
    name: String,
    dummy_min_ms: u64,
    dummy_max_ms: u64,
    no_dummy: bool,
}

#[derive(Debug, Clone)]
struct TuiConfig {
    runtime: RuntimeConfig,
    initial_target: String,
    show_dummy: bool,
    used_demo_key: bool,
    used_default_name: bool,
}

struct ListenRuntime {
    socket: UdpSocket,
    key: [u8; 32],
}

struct NonceCache {
    seen: HashSet<[u8; 12]>,
    order: VecDeque<[u8; 12]>,
    cap: usize,
}

impl NonceCache {
    fn new(cap: usize) -> Self {
        Self {
            seen: HashSet::with_capacity(cap),
            order: VecDeque::with_capacity(cap),
            cap,
        }
    }

    fn insert(&mut self, nonce: [u8; 12]) -> bool {
        if self.seen.contains(&nonce) {
            return false;
        }

        if self.order.len() >= self.cap {
            if let Some(expired) = self.order.pop_front() {
                self.seen.remove(&expired);
            }
        }

        self.order.push_back(nonce);
        self.seen.insert(nonce);
        true
    }
}

struct ReceivedPacket {
    packet: PlainPacket,
    src: SocketAddr,
}

enum WireEvent {
    Packet(ReceivedPacket),
    Error(String),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FocusField {
    Target,
    Message,
}

#[derive(Clone, Copy)]
enum LogKind {
    System,
    Incoming,
    Outgoing,
    Dummy,
    Error,
}

struct LogLine {
    kind: LogKind,
    text: String,
}

impl LogLine {
    fn into_line(self) -> Line<'static> {
        let style = match self.kind {
            LogKind::System => Style::default().fg(Color::Cyan),
            LogKind::Incoming => Style::default().fg(Color::Green),
            LogKind::Outgoing => Style::default().fg(Color::Yellow),
            LogKind::Dummy => Style::default().fg(Color::DarkGray),
            LogKind::Error => Style::default().fg(Color::Red),
        };
        Line::styled(self.text, style)
    }
}

struct TuiApp {
    node_name: String,
    bind: SocketAddr,
    broadcast: SocketAddr,
    cover_enabled: bool,
    show_dummy: bool,
    focus: FocusField,
    target: String,
    input: String,
    logs: VecDeque<LogLine>,
    message_count: u64,
    dummy_count: u64,
    outgoing_seq: u32,
    should_quit: bool,
}

impl TuiApp {
    fn new(config: &TuiConfig) -> Self {
        Self {
            node_name: config.runtime.name.clone(),
            bind: config.runtime.bind,
            broadcast: config.runtime.broadcast,
            cover_enabled: !config.runtime.no_dummy,
            show_dummy: config.show_dummy,
            focus: FocusField::Message,
            target: config.initial_target.clone(),
            input: String::new(),
            logs: VecDeque::with_capacity(256),
            message_count: 0,
            dummy_count: 0,
            outgoing_seq: 1,
            should_quit: false,
        }
    }

    fn push_log(&mut self, kind: LogKind, text: impl Into<String>) {
        if self.logs.len() >= 200 {
            self.logs.pop_front();
        }
        self.logs.push_back(LogLine {
            kind,
            text: text.into(),
        });
    }

    fn current_input_mut(&mut self) -> &mut String {
        match self.focus {
            FocusField::Target => &mut self.target,
            FocusField::Message => &mut self.input,
        }
    }

    fn toggle_focus(&mut self) {
        self.focus = match self.focus {
            FocusField::Target => FocusField::Message,
            FocusField::Message => FocusField::Target,
        };
    }

    fn normalized_target(&self) -> String {
        let trimmed = self.target.trim();
        if trimmed.is_empty() {
            "all".to_string()
        } else {
            trimmed.to_string()
        }
    }

    fn handle_wire_event(&mut self, event: WireEvent) {
        match event {
            WireEvent::Packet(received) => match received.packet.kind {
                PacketKind::Dummy => {
                    self.dummy_count = self.dummy_count.saturating_add(1);
                    if self.show_dummy {
                        self.push_log(
                            LogKind::Dummy,
                            format!(
                                "[掩护包] 来自={} 源地址={} 序号={} 时间戳={}",
                                received.packet.sender,
                                received.src,
                                received.packet.sequence,
                                received.packet.sent_at
                            ),
                        );
                    }
                }
                PacketKind::Message => {
                    if received.packet.sender == self.node_name {
                        return;
                    }
                    self.message_count = self.message_count.saturating_add(1);
                    self.push_log(
                        LogKind::Incoming,
                        format!(
                            "[密语] {} -> {}：{}",
                            received.packet.sender, received.packet.target, received.packet.body
                        ),
                    );
                }
            },
            WireEvent::Error(message) => self.push_log(LogKind::Error, message),
        }
    }
}

struct CoverTrafficArgs {
    socket: UdpSocket,
    broadcast: SocketAddr,
    key: [u8; 32],
    sender_name: String,
    min_sleep_ms: u64,
    max_sleep_ms: u64,
}

struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let mut stdout = io::stdout();
        let _ = execute!(stdout, LeaveAlternateScreen);
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::GenKey => {
            println!("{}", generate_key_hex());
            Ok(())
        }
        Command::Send(args) => send_command(args),
        Command::Listen(args) => listen_command(args),
        Command::Tui(args) => tui_command(args),
    }
}

fn send_command(args: SendArgs) -> Result<()> {
    let key = parse_key_hex(&args.key).context("解析共享密钥失败")?;
    validate_label(&args.sender, "发送者代号")?;
    validate_label(&args.target, "目标名")?;
    validate_body(&args.message)?;

    let socket = build_udp_socket(args.bind)?;
    let payload = PlainPacket {
        kind: PacketKind::Message,
        sender: args.sender,
        target: args.target,
        sent_at: unix_timestamp(),
        sequence: 1,
        body: args.message,
    };

    send_payload(&socket, args.broadcast, &key, &payload)?;
    println!(
        "已发送 1 条加密广播消息，发送者={}，目标={}，广播地址={}",
        payload.sender, payload.target, args.broadcast
    );
    Ok(())
}

fn listen_command(args: ListenArgs) -> Result<()> {
    let config = resolve_listen_args(&args.shared)?;
    let runtime = prepare_listener(&config)?;
    print_listener_banner(&config);

    let mut seen_nonces = NonceCache::new(1024);
    loop {
        match receive_packet(
            &runtime.socket,
            &runtime.key,
            &config.name,
            &mut seen_nonces,
        ) {
            Ok(Some(received)) => match received.packet.kind {
                PacketKind::Dummy if args.print_dummy => {
                    println!(
                        "[掩护包] 来自={} 源地址={} 序号={} 时间戳={}",
                        received.packet.sender,
                        received.src,
                        received.packet.sequence,
                        received.packet.sent_at
                    );
                }
                PacketKind::Dummy => {}
                PacketKind::Message => {
                    println!(
                        "[密语] 来自={} 目标={} 源地址={} 时间戳={} 序号={} 内容={}",
                        received.packet.sender,
                        received.packet.target,
                        received.src,
                        received.packet.sent_at,
                        received.packet.sequence,
                        received.packet.body
                    );
                }
            },
            Ok(None) => {}
            Err(err) => eprintln!("接收 UDP 数据包失败: {err}"),
        }
    }
}

fn tui_command(args: TuiArgs) -> Result<()> {
    let config = resolve_tui_args(args)?;
    let runtime = prepare_listener(&config.runtime)?;
    let receive_socket = runtime
        .socket
        .try_clone()
        .context("复制 TUI 监听 socket 失败")?;
    let (tx, rx) = mpsc::channel();
    spawn_receiver_thread(receive_socket, runtime.key, config.runtime.name.clone(), tx);

    let mut app = TuiApp::new(&config);
    app.push_log(
        LogKind::System,
        format!(
            "已加入宿舍频道，当前代号={}，当前目标={}",
            app.node_name,
            app.normalized_target()
        ),
    );
    if config.used_default_name {
        app.push_log(
            LogKind::System,
            format!("未手动填写节点代号，已使用默认代号：{}", app.node_name),
        );
    }
    if config.used_demo_key {
        app.push_log(
            LogKind::System,
            "当前使用课堂演示默认密钥。真实使用建议先执行 gen-key，再把同一把密钥分给室友。",
        );
    }
    app.push_log(
        LogKind::System,
        "操作提示：Tab 切换输入框，Enter 发送，F2 切换掩护包显示，Ctrl+U 清空当前输入，Esc 退出",
    );

    run_tui_loop(runtime.socket, runtime.key, rx, &mut app)
}

fn resolve_listen_args(args: &SharedListenArgs) -> Result<RuntimeConfig> {
    validate_runtime_fields(
        args.name.trim(),
        args.dummy_min_ms,
        args.dummy_max_ms,
        Some("all"),
    )?;

    Ok(RuntimeConfig {
        bind: args.bind,
        broadcast: args.broadcast,
        key: parse_key_hex(&args.key).context("解析共享密钥失败")?,
        name: args.name.trim().to_string(),
        dummy_min_ms: args.dummy_min_ms,
        dummy_max_ms: args.dummy_max_ms,
        no_dummy: args.no_dummy,
    })
}

fn resolve_tui_args(args: TuiArgs) -> Result<TuiConfig> {
    let (key_text, used_demo_key) = if let Some(key) = args.key.filter(|key| !key.trim().is_empty())
    {
        (key, false)
    } else {
        prompt_line_with_default("共享密钥（64 位十六进制）", DEMO_SHARED_KEY_HEX)?
    };

    let fallback_name = default_node_name();
    let (name, used_default_name) =
        if let Some(name) = args.name.filter(|name| !name.trim().is_empty()) {
            (name, false)
        } else {
            prompt_line_with_default("节点代号（最多 16 字节）", &fallback_name)?
        };

    validate_runtime_fields(
        name.trim(),
        args.dummy_min_ms,
        args.dummy_max_ms,
        Some(&args.target),
    )?;

    Ok(TuiConfig {
        runtime: RuntimeConfig {
            bind: args.bind,
            broadcast: args.broadcast,
            key: parse_key_hex(&key_text).context("解析共享密钥失败")?,
            name: name.trim().to_string(),
            dummy_min_ms: args.dummy_min_ms,
            dummy_max_ms: args.dummy_max_ms,
            no_dummy: args.no_dummy,
        },
        initial_target: args.target.trim().to_string(),
        show_dummy: args.show_dummy,
        used_demo_key,
        used_default_name,
    })
}

fn validate_runtime_fields(
    name: &str,
    dummy_min_ms: u64,
    dummy_max_ms: u64,
    initial_target: Option<&str>,
) -> Result<()> {
    ensure!(!name.is_empty(), "节点代号不能为空");
    validate_label(name, "节点代号")?;

    if let Some(target) = initial_target {
        validate_label(target, "目标名")?;
    }

    if dummy_min_ms > dummy_max_ms {
        bail!("dummy_min_ms 不能大于 dummy_max_ms");
    }

    Ok(())
}

fn prompt_line_with_default(label: &str, default: &str) -> Result<(String, bool)> {
    print!("{label} [默认: {default}]: ");
    io::stdout().flush().context("刷新终端输出失败")?;

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .context("读取终端输入失败")?;

    let trimmed = input.trim();
    if trimmed.is_empty() {
        Ok((default.to_string(), true))
    } else {
        Ok((trimmed.to_string(), false))
    }
}

fn prepare_listener(config: &RuntimeConfig) -> Result<ListenRuntime> {
    let socket = build_udp_socket(config.bind)?;
    socket
        .set_read_timeout(Some(Duration::from_millis(250)))
        .context("设置读取超时失败")?;

    if !config.no_dummy {
        let socket_for_cover = socket.try_clone().context("复制 UDP socket 失败")?;
        let cover_args = CoverTrafficArgs {
            socket: socket_for_cover,
            broadcast: config.broadcast,
            key: config.key,
            sender_name: config.name.clone(),
            min_sleep_ms: config.dummy_min_ms,
            max_sleep_ms: config.dummy_max_ms,
        };
        thread::spawn(move || run_cover_traffic(cover_args));
    }

    Ok(ListenRuntime {
        socket,
        key: config.key,
    })
}

fn print_listener_banner(config: &RuntimeConfig) {
    println!(
        "黑暗森林节点已启动：监听地址={}，掩护流量广播地址={}，本机代号={}",
        config.bind, config.broadcast, config.name
    );
    if config.no_dummy {
        println!("当前模式：仅监听，不发送 dummy 掩护流量");
    } else {
        println!(
            "当前模式：已开启 dummy 掩护流量，随机间隔 {}-{} ms",
            config.dummy_min_ms, config.dummy_max_ms
        );
    }
}

fn spawn_receiver_thread(
    socket: UdpSocket,
    key: [u8; 32],
    local_name: String,
    tx: mpsc::Sender<WireEvent>,
) {
    thread::spawn(move || {
        let mut seen_nonces = NonceCache::new(1024);
        loop {
            match receive_packet(&socket, &key, &local_name, &mut seen_nonces) {
                Ok(Some(received)) => {
                    if tx.send(WireEvent::Packet(received)).is_err() {
                        break;
                    }
                }
                Ok(None) => {}
                Err(err) => {
                    if tx
                        .send(WireEvent::Error(format!("接收 UDP 数据包失败: {err}")))
                        .is_err()
                    {
                        break;
                    }
                    thread::sleep(Duration::from_millis(200));
                }
            }
        }
    });
}

fn receive_packet(
    socket: &UdpSocket,
    key: &[u8; 32],
    local_name: &str,
    seen_nonces: &mut NonceCache,
) -> io::Result<Option<ReceivedPacket>> {
    let mut buf = [0_u8; PACKET_LEN];
    match socket.recv_from(&mut buf) {
        Ok((len, src)) => {
            if len != PACKET_LEN {
                return Ok(None);
            }

            let nonce = match nonce_from_packet(&buf[..len]) {
                Ok(nonce) => nonce,
                Err(_) => return Ok(None),
            };
            if !seen_nonces.insert(nonce) {
                return Ok(None);
            }

            let packet = match open_packet(key, &buf[..len]) {
                Ok(packet) => packet,
                Err(_) => return Ok(None),
            };
            if !is_for_me(&packet.target, local_name) {
                return Ok(None);
            }

            Ok(Some(ReceivedPacket { packet, src }))
        }
        Err(err) if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => Ok(None),
        Err(err) => Err(err),
    }
}

fn run_tui_loop(
    send_socket: UdpSocket,
    key: [u8; 32],
    rx: mpsc::Receiver<WireEvent>,
    app: &mut TuiApp,
) -> Result<()> {
    enable_raw_mode().context("开启终端原始模式失败")?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).context("切换到终端全屏界面失败")?;
    let _guard = TerminalGuard;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("创建 TUI 终端失败")?;
    terminal.clear().context("清空终端失败")?;

    loop {
        while let Ok(event) = rx.try_recv() {
            app.handle_wire_event(event);
        }

        terminal
            .draw(|frame| draw_tui(frame, app))
            .context("刷新 TUI 界面失败")?;

        if app.should_quit {
            break;
        }

        if event::poll(Duration::from_millis(120)).context("读取终端事件失败")? {
            if let Event::Key(key_event) = event::read().context("读取按键失败")? {
                if key_event.kind == KeyEventKind::Press {
                    handle_tui_key(key_event, app, &send_socket, &key)?;
                }
            }
        }
    }

    terminal.show_cursor().context("恢复光标显示失败")?;
    Ok(())
}

fn handle_tui_key(
    key_event: KeyEvent,
    app: &mut TuiApp,
    send_socket: &UdpSocket,
    key: &[u8; 32],
) -> Result<()> {
    if key_event.modifiers.contains(KeyModifiers::CONTROL) {
        match key_event.code {
            KeyCode::Char('c') => {
                app.should_quit = true;
                return Ok(());
            }
            KeyCode::Char('u') => {
                app.current_input_mut().clear();
                return Ok(());
            }
            _ => {}
        }
    }

    match key_event.code {
        KeyCode::Esc => app.should_quit = true,
        KeyCode::Tab | KeyCode::BackTab => app.toggle_focus(),
        KeyCode::F(2) => {
            app.show_dummy = !app.show_dummy;
            app.push_log(
                LogKind::System,
                if app.show_dummy {
                    "已开启掩护包显示"
                } else {
                    "已关闭掩护包显示"
                },
            );
        }
        KeyCode::Enter => match app.focus {
            FocusField::Target => app.focus = FocusField::Message,
            FocusField::Message => submit_tui_message(app, send_socket, key),
        },
        KeyCode::Backspace => {
            app.current_input_mut().pop();
        }
        KeyCode::Char(ch)
            if key_event.modifiers.is_empty() || key_event.modifiers == KeyModifiers::SHIFT =>
        {
            push_char_to_focused_field(app, ch);
        }
        _ => {}
    }

    Ok(())
}

fn push_char_to_focused_field(app: &mut TuiApp, ch: char) {
    match app.focus {
        FocusField::Target => {
            let next_len = app.target.len() + ch.len_utf8();
            if next_len <= LABEL_LEN {
                app.target.push(ch);
            } else {
                app.push_log(LogKind::Error, format!("目标名最多只能占 {LABEL_LEN} 字节"));
            }
        }
        FocusField::Message => {
            let next_len = app.input.len() + ch.len_utf8();
            if next_len <= BODY_LEN {
                app.input.push(ch);
            } else {
                app.push_log(
                    LogKind::Error,
                    format!("消息正文最多只能占 {BODY_LEN} 字节"),
                );
            }
        }
    }
}

fn submit_tui_message(app: &mut TuiApp, send_socket: &UdpSocket, key: &[u8; 32]) {
    let body = app.input.trim().to_string();
    if body.is_empty() {
        app.push_log(LogKind::System, "消息为空，未发送");
        return;
    }

    let target = app.normalized_target();
    let payload = PlainPacket {
        kind: PacketKind::Message,
        sender: app.node_name.clone(),
        target: target.clone(),
        sent_at: unix_timestamp(),
        sequence: app.outgoing_seq,
        body: body.clone(),
    };
    app.outgoing_seq = app.outgoing_seq.wrapping_add(1);

    match send_payload(send_socket, app.broadcast, key, &payload) {
        Ok(()) => {
            app.push_log(LogKind::Outgoing, format!("[我 -> {}] {}", target, body));
            app.input.clear();
        }
        Err(err) => app.push_log(LogKind::Error, format!("发送失败: {err:#}")),
    }
}

fn draw_tui(frame: &mut Frame<'_>, app: &TuiApp) {
    let areas = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Min(8),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(2),
        ])
        .split(frame.area());

    let header_text = Text::from(vec![
        Line::from(vec![
            Span::styled("节点：", Style::default().fg(Color::Cyan)),
            Span::raw(app.node_name.clone()),
            Span::raw("  "),
            Span::styled("监听：", Style::default().fg(Color::Cyan)),
            Span::raw(app.bind.to_string()),
            Span::raw("  "),
            Span::styled("广播：", Style::default().fg(Color::Cyan)),
            Span::raw(app.broadcast.to_string()),
        ]),
        Line::from(vec![
            Span::styled("当前目标：", Style::default().fg(Color::Cyan)),
            Span::raw(app.normalized_target()),
            Span::raw("  "),
            Span::styled("掩护流量：", Style::default().fg(Color::Cyan)),
            Span::raw(if app.cover_enabled {
                "开启"
            } else {
                "关闭"
            }),
            Span::raw("  "),
            Span::styled("掩护包显示：", Style::default().fg(Color::Cyan)),
            Span::raw(if app.show_dummy { "显示" } else { "隐藏" }),
            Span::raw("  "),
            Span::styled("密语数：", Style::default().fg(Color::Cyan)),
            Span::raw(app.message_count.to_string()),
            Span::raw("  "),
            Span::styled("掩护包数：", Style::default().fg(Color::Cyan)),
            Span::raw(app.dummy_count.to_string()),
        ]),
    ]);
    let header = Paragraph::new(header_text)
        .block(Block::default().borders(Borders::ALL).title("黑暗森林"))
        .wrap(Wrap { trim: false });
    frame.render_widget(header, areas[0]);

    let visible_logs = areas[1].height.saturating_sub(2) as usize;
    let mut recent_logs = app
        .logs
        .iter()
        .rev()
        .take(visible_logs.max(1))
        .map(|line| LogLine {
            kind: line.kind,
            text: line.text.clone(),
        })
        .collect::<Vec<_>>();
    recent_logs.reverse();
    let log_text = Text::from(
        recent_logs
            .into_iter()
            .map(LogLine::into_line)
            .collect::<Vec<_>>(),
    );
    let message_panel = Paragraph::new(log_text)
        .block(Block::default().borders(Borders::ALL).title("消息流"))
        .wrap(Wrap { trim: false });
    frame.render_widget(message_panel, areas[1]);

    let target_block = Block::default()
        .borders(Borders::ALL)
        .title(format!("目标（{} / {} 字节）", app.target.len(), LABEL_LEN))
        .border_style(if app.focus == FocusField::Target {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default()
        });
    let target_inner = target_block.inner(areas[2]);
    let target_text = if app.target.is_empty() {
        Line::styled("all", Style::default().fg(Color::DarkGray))
    } else {
        Line::raw(app.target.clone())
    };
    frame.render_widget(Paragraph::new(target_text).block(target_block), areas[2]);

    let message_block = Block::default()
        .borders(Borders::ALL)
        .title(format!("输入（{} / {} 字节）", app.input.len(), BODY_LEN))
        .border_style(if app.focus == FocusField::Message {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default()
        });
    let message_inner = message_block.inner(areas[3]);
    let message_text = if app.input.is_empty() {
        Line::styled(
            "在这里输入密语，按 Enter 发送",
            Style::default().fg(Color::DarkGray),
        )
    } else {
        Line::raw(app.input.clone())
    };
    frame.render_widget(Paragraph::new(message_text).block(message_block), areas[3]);

    let footer = Paragraph::new(Line::from(vec![
        Span::styled("Tab", Style::default().fg(Color::Yellow)),
        Span::raw(" 切换输入框  "),
        Span::styled("Enter", Style::default().fg(Color::Yellow)),
        Span::raw(" 发送  "),
        Span::styled("F2", Style::default().fg(Color::Yellow)),
        Span::raw(" 显示/隐藏掩护包  "),
        Span::styled("Ctrl+U", Style::default().fg(Color::Yellow)),
        Span::raw(" 清空当前输入  "),
        Span::styled("Esc", Style::default().fg(Color::Yellow)),
        Span::raw(" 退出"),
    ]))
    .block(Block::default().borders(Borders::ALL).title("快捷键"));
    frame.render_widget(footer, areas[4]);

    match app.focus {
        FocusField::Target => {
            let cursor_x = target_inner.x
                + UnicodeWidthStr::width(app.target.as_str())
                    .min(target_inner.width.saturating_sub(1) as usize) as u16;
            frame.set_cursor_position((cursor_x, target_inner.y));
        }
        FocusField::Message => {
            let cursor_x = message_inner.x
                + UnicodeWidthStr::width(app.input.as_str())
                    .min(message_inner.width.saturating_sub(1) as usize) as u16;
            frame.set_cursor_position((cursor_x, message_inner.y));
        }
    }
}

fn run_cover_traffic(args: CoverTrafficArgs) {
    let mut seq = 1_u32;
    let mut rng = rand::thread_rng();

    loop {
        let sleep_ms = rng.gen_range(args.min_sleep_ms..=args.max_sleep_ms);
        thread::sleep(Duration::from_millis(sleep_ms));

        let payload = PlainPacket {
            kind: PacketKind::Dummy,
            sender: args.sender_name.clone(),
            target: String::new(),
            sent_at: unix_timestamp(),
            sequence: seq,
            body: String::new(),
        };
        seq = seq.wrapping_add(1);

        if let Err(err) = send_payload(&args.socket, args.broadcast, &args.key, &payload) {
            eprintln!("发送 dummy 掩护包失败: {err:#}");
        }
    }
}

fn send_payload(
    socket: &UdpSocket,
    broadcast: SocketAddr,
    key: &[u8; 32],
    payload: &PlainPacket,
) -> Result<()> {
    let packet = seal_packet(key, payload, &mut OsRng).context("加密数据包失败")?;
    socket
        .send_to(&packet, broadcast)
        .with_context(|| format!("向 {broadcast} 发送 UDP 数据包失败"))?;
    Ok(())
}

fn build_udp_socket(bind_addr: SocketAddr) -> Result<UdpSocket> {
    let domain = match bind_addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };

    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
        .with_context(|| format!("为 {bind_addr} 创建 UDP socket 失败"))?;
    socket
        .set_reuse_address(true)
        .context("开启 SO_REUSEADDR 失败")?;

    #[cfg(unix)]
    socket.set_reuse_port(true).ok();

    if matches!(bind_addr, SocketAddr::V4(_)) {
        socket
            .set_broadcast(true)
            .context("开启 SO_BROADCAST 失败")?;
    }

    socket
        .bind(&bind_addr.into())
        .with_context(|| format!("绑定 UDP socket 到 {bind_addr} 失败"))?;

    Ok(socket.into())
}

fn validate_label(value: &str, field_name: &str) -> Result<()> {
    let trimmed = value.trim();
    if trimmed.eq_ignore_ascii_case("all") || trimmed.is_empty() {
        return Ok(());
    }

    ensure!(
        trimmed.len() <= LABEL_LEN,
        "{field_name} 最多只能占 {LABEL_LEN} 字节"
    );
    Ok(())
}

fn validate_body(body: &str) -> Result<()> {
    ensure!(body.len() <= BODY_LEN, "消息正文最多只能占 {BODY_LEN} 字节");
    Ok(())
}

fn default_node_name() -> String {
    for candidate in [
        std::env::var("HOSTNAME").ok(),
        std::env::var("USER").ok(),
        Some("roommate".to_string()),
    ]
    .into_iter()
    .flatten()
    {
        let trimmed = candidate.trim();
        if trimmed.is_empty() {
            continue;
        }

        let truncated = truncate_utf8_to_bytes(trimmed, LABEL_LEN);
        if !truncated.is_empty() {
            return truncated;
        }
    }

    "roommate".to_string()
}

fn truncate_utf8_to_bytes(input: &str, max_bytes: usize) -> String {
    let mut out = String::new();
    let mut used = 0;
    for ch in input.chars() {
        let len = ch.len_utf8();
        if used + len > max_bytes {
            break;
        }
        out.push(ch);
        used += len;
    }
    out
}

fn is_for_me(target: &str, local_name: &str) -> bool {
    target.is_empty() || target == local_name || target.eq_ignore_ascii_case("all")
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_secs()
}
