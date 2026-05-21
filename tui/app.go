package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/networkshard/shardlure/internal/store"
)

type tickMsg time.Time

type model struct {
	st        *store.Store
	dbPath    string
	actors    table.Model
	events    viewport.Model
	detail    viewport.Model
	actorRows []table.Row
	cursor    int
	width     int
	height    int
	err       error
}

var (
	titleStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("205"))
	dimStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	accentStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("39"))
)

func Run(st *store.Store, dbPath string) error {
	m := newModel(st, dbPath)
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}

func newModel(st *store.Store, dbPath string) *model {
	cols := []table.Column{
		{Title: "IP", Width: 16},
		{Title: "Playbook", Width: 22},
		{Title: "Ev", Width: 6},
		{Title: "Rate/h", Width: 8},
		{Title: "Last", Width: 12},
	}
	t := table.New(
		table.WithColumns(cols),
		table.WithHeight(12),
		table.WithFocused(true),
	)
	t.SetStyles(table.Styles{
		Header:   titleStyle,
		Selected: lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("229")).Background(lipgloss.Color("57")),
	})

	ev := viewport.New(80, 8)
	dt := viewport.New(80, 10)
	m := &model{st: st, dbPath: dbPath, actors: t, events: ev, detail: dt}
	_ = m.loadData()
	return m
}

func (m *model) Init() tea.Cmd {
	return tick()
}

func tick() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func (m *model) loadData() error {
	list, err := m.st.ListActors(30)
	if err != nil {
		return err
	}
	var rows []table.Row
	for _, a := range list {
		rows = append(rows, table.Row{
			a.PrimaryIP,
			a.Playbook,
			fmt.Sprintf("%d", a.EventCount),
			fmt.Sprintf("%.0f", a.AttemptsPerHour),
			relTime(a.LastSeen),
		})
	}
	m.actorRows = rows
	m.actors.SetRows(rows)
	if m.cursor >= len(rows) {
		m.cursor = 0
	}
	m.actors.SetCursor(m.cursor)
	return m.refreshPanels()
}

func (m *model) refreshPanels() error {
	events, err := m.st.RecentEvents(40)
	if err != nil {
		return err
	}
	var eb strings.Builder
	now := time.Now()
	for _, e := range events {
		ago := now.Sub(e.TS).Truncate(time.Second)
		kindStr := string(e.Kind)
		if len(kindStr) > 12 {
			kindStr = kindStr[:12]
		}
		eb.WriteString(fmt.Sprintf("%s  %s  %-14s  %s  %s\n",
			dimStyle.Render(fmt.Sprintf("%-8s", ago)),
			kindStr,
			e.SrcIP,
			e.Username,
			trunc(e.ActorID, 18)))
	}
	m.events.SetContent(eb.String())

	list, _ := m.st.ListActors(30)
	if m.cursor < len(list) {
		a := list[m.cursor]
		users, _ := m.st.ActorUsers(a.ID)
		var db strings.Builder
		db.WriteString(titleStyle.Render("Actor ") + a.PrimaryIP + "\n\n")
		db.WriteString(fmt.Sprintf("  id:       %s\n", a.ID))
		db.WriteString(fmt.Sprintf("  playbook: %s\n", accentStyle.Render(a.Playbook)))
		db.WriteString(fmt.Sprintf("  events:   %d  users: %d  rate: %.0f/h\n", a.EventCount, a.UniqueUsers, a.AttemptsPerHour))
		db.WriteString(fmt.Sprintf("  seen:     %s -> %s\n", a.FirstSeen.Format(time.RFC3339), relTime(a.LastSeen)))
		db.WriteString(fmt.Sprintf("  fp hash:  %s\n\n", a.UsernameHash))
		db.WriteString("Top usernames:\n")
		for i, u := range users {
			if i >= 12 {
				break
			}
			db.WriteString(fmt.Sprintf("  %5d  %s\n", u.Count, u.Username))
		}
		m.detail.SetContent(db.String())
	}
	return nil
}

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
				m.actors.SetCursor(m.cursor)
				_ = m.refreshPanels()
			}
		case "down", "j":
			if m.cursor < len(m.actorRows)-1 {
				m.cursor++
				m.actors.SetCursor(m.cursor)
				_ = m.refreshPanels()
			}
		case "r":
			_ = m.loadData()
		}
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.actors.SetWidth(msg.Width - 4)
		m.events.Width = msg.Width - 4
		m.events.Height = 8
		m.detail.Width = msg.Width - 4
		m.detail.Height = msg.Height - 22
	case tickMsg:
		_ = m.refreshPanels()
		return m, tick()
	}

	var cmd tea.Cmd
	m.actors, cmd = m.actors.Update(msg)
	return m, tea.Batch(cmd, tick())
}

func (m *model) View() string {
	if m.err != nil {
		return fmt.Sprintf("error: %v\n", m.err)
	}
	header := titleStyle.Render("ShardLure") + dimStyle.Render("  actor identity  ") + dimStyle.Render("q quit | j/k move | r reload")
	return lipgloss.JoinVertical(lipgloss.Left,
		header,
		"",
		titleStyle.Render("Actors"),
		m.actors.View(),
		"",
		lipgloss.JoinHorizontal(lipgloss.Top,
			lipgloss.NewStyle().Width(m.width/2).Render(titleStyle.Render("Live feed")+"\n"+m.events.View()),
			lipgloss.NewStyle().Width(m.width/2).Render(titleStyle.Render("Actor detail")+"\n"+m.detail.View()),
		),
		dimStyle.Render(m.dbPath),
	)
}

func relTime(t time.Time) string {
	d := time.Since(t)
	if d < time.Minute {
		return fmt.Sprintf("%.0fs ago", d.Seconds())
	}
	if d < time.Hour {
		return fmt.Sprintf("%.0fm ago", d.Minutes())
	}
	return fmt.Sprintf("%.0fh ago", d.Hours())
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}
