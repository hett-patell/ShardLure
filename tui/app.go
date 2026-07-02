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
	"github.com/networkshard/shardlure/pkg/models"
)

type tickMsg time.Time

type model struct {
	st     *store.Store
	dbPath string
	actors table.Model
	events viewport.Model
	detail viewport.Model
	// actorList is the snapshot backing the table rows. The detail panel
	// must read from this same snapshot — re-querying ListActors for the
	// detail while the table shows older rows made the two panels describe
	// different actors (the list re-sorts by last_seen as events arrive).
	actorList []models.Actor
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
	m.refresh()
	return m
}

func (m *model) Init() tea.Cmd {
	return tick()
}

func tick() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg { return tickMsg(t) })
}

// refresh reloads everything and records any failure in m.err so View can
// surface it instead of silently freezing on stale data. A later successful
// refresh clears the error.
func (m *model) refresh() {
	if err := m.reload(); err != nil {
		m.err = err
		return
	}
	m.err = nil
}

func (m *model) reload() error {
	list, err := m.st.ListActors(30)
	if err != nil {
		return fmt.Errorf("list actors: %w", err)
	}
	m.actorList = list
	rows := make([]table.Row, 0, len(list))
	for _, a := range list {
		rows = append(rows, table.Row{
			a.PrimaryIP,
			a.Playbook,
			fmt.Sprintf("%d", a.EventCount),
			fmt.Sprintf("%.0f", a.AttemptsPerHour),
			relTime(a.LastSeen),
		})
	}
	m.actors.SetRows(rows)
	if m.actors.Cursor() >= len(rows) {
		m.actors.SetCursor(0)
	}

	events, err := m.st.RecentEvents(40)
	if err != nil {
		return fmt.Errorf("recent events: %w", err)
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

	return m.renderDetail()
}

// renderDetail rebuilds the detail panel for the actor under the table
// cursor, reading from the same snapshot the table rows were built from.
func (m *model) renderDetail() error {
	cur := m.actors.Cursor()
	if cur < 0 || cur >= len(m.actorList) {
		m.detail.SetContent(dimStyle.Render("no actors yet"))
		return nil
	}
	a := m.actorList[cur]
	users, err := m.st.ActorUsersLimit(a.ID, 12)
	if err != nil {
		return fmt.Errorf("actor users: %w", err)
	}
	var db strings.Builder
	db.WriteString(titleStyle.Render("Actor ") + a.PrimaryIP + "\n\n")
	db.WriteString(fmt.Sprintf("  id:       %s\n", a.ID))
	db.WriteString(fmt.Sprintf("  playbook: %s\n", accentStyle.Render(a.Playbook)))
	db.WriteString(fmt.Sprintf("  events:   %d  users: %d  rate: %.0f/h\n", a.EventCount, a.UniqueUsers, a.AttemptsPerHour))
	db.WriteString(fmt.Sprintf("  seen:     %s -> %s\n", a.FirstSeen.Format(time.RFC3339), relTime(a.LastSeen)))
	db.WriteString(fmt.Sprintf("  fp hash:  %s\n\n", a.UsernameHash))
	db.WriteString("Top usernames:\n")
	for _, u := range users {
		db.WriteString(fmt.Sprintf("  %5d  %s\n", u.Count, u.Username))
	}
	m.detail.SetContent(db.String())
	return nil
}

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "up", "k", "down", "j":
			// The table's own keymap binds these; let it move the cursor
			// exactly once, then re-render the detail for the new selection.
			// (Handling movement here AND falling through to table.Update
			// moved the cursor twice, leaving the highlight permanently one
			// row ahead of the detail panel.)
			var cmd tea.Cmd
			m.actors, cmd = m.actors.Update(msg)
			if err := m.renderDetail(); err != nil {
				m.err = err
			}
			return m, cmd
		case "r":
			m.refresh()
			return m, nil
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
		m.refresh()
		return m, tick()
	}

	var cmd tea.Cmd
	m.actors, cmd = m.actors.Update(msg)
	// Do NOT schedule a tick here. The tick loop is self-sustaining: Init()
	// fires the first tick and the tickMsg case reschedules each subsequent
	// one. Rescheduling on every message (key presses, resize, mouse) spawned
	// an extra concurrent tick timer per event, compounding without bound.
	return m, cmd
}

func (m *model) View() string {
	header := titleStyle.Render("ShardLure") + dimStyle.Render("  actor identity  ") + dimStyle.Render("q quit | j/k move | r reload")
	body := lipgloss.JoinVertical(lipgloss.Left,
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
	if m.err != nil {
		body = lipgloss.JoinVertical(lipgloss.Left, body,
			lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Render(fmt.Sprintf("error: %v (retrying)", m.err)))
	}
	return body
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
