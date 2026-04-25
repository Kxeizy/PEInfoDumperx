using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Linq;
using System.Collections.Generic;
using System.Windows.Forms;
using PEInfoDumperx.Core;
using PEInfoDumperx.Models;

namespace PEInfoDumperx.UI
{
    public partial class MainForm : Form
    {
        // UI controls
        private Panel? sidePanel, headerPanel, mainContainer, emptyState;
        private Button? btnDashboard, btnStrings, btnImports, btnLoad;
        private TabControl? tabMain;
        private TabPage? tabDashboard, tabStrings, tabImports;
        private RichTextBox? txtInfo;
        private DataGridView? gridSections;
        private TreeView? treeImports;
        private ListView? listExports, listStrings;
        private TextBox? txtSearchStrings;
        private ToolStripStatusLabel? lblStatus, lblFile;
        private StatusStrip? statusStrip;

        // Animation timers and tracking variables
        private System.Windows.Forms.Timer? globalTimer;
        private int progressTarget = 0;
        private float currentProgress = 0f;
        private Panel? progressBarCustom;

        private Panel? navIndicator;
        private float navIndicatorTargetY = 0f;
        private float navIndicatorCurrentY = 0f;

        private List<string> currentStrings = new();
        private Button? activeNavBtn;

        // Color palette
        private static readonly Color C_BG = Color.FromArgb(10, 10, 14);
        private static readonly Color C_SIDEBAR = Color.FromArgb(16, 16, 22);
        private static readonly Color C_SURFACE = Color.FromArgb(22, 23, 30);
        private static readonly Color C_CARD = Color.FromArgb(28, 30, 40);
        private static readonly Color C_BORDER = Color.FromArgb(45, 48, 65);
        private static readonly Color C_ACCENT = Color.FromArgb(0, 120, 215);
        private static readonly Color C_ACCENT2 = Color.FromArgb(130, 50, 255);
        private static readonly Color C_TEXT = Color.FromArgb(220, 225, 235);
        private static readonly Color C_TEXT_SEC = Color.FromArgb(110, 125, 150);
        private static readonly Color C_SUCCESS = Color.FromArgb(0, 230, 118);
        private static readonly Color C_DANGER = Color.FromArgb(255, 61, 87);

        public MainForm()
        {
            this.DoubleBuffered = true;
            this.SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer, true);
            InitializeUI();
            WireDropEvents();
        }

        private void WireDropEvents()
        {
            this.AllowDrop = true;
            this.DragEnter += (s, e) => { if (e.Data!.GetDataPresent(DataFormats.FileDrop)) e.Effect = DragDropEffects.Copy; };
            this.DragDrop += (s, e) => {
                var files = (string[]?)e.Data!.GetData(DataFormats.FileDrop);
                if (files?.Length > 0) AnalyzeFile(files[0]);
            };
        }

        private void InitializeUI()
        {
            this.Text = "PEInfoDumperx | Forensic Analysis Suite";
            this.Size = new Size(1400, 950);
            this.MinimumSize = new Size(1100, 800);
            this.BackColor = C_BG;
            this.Font = new Font("Segoe UI", 10F);
            this.StartPosition = FormStartPosition.CenterScreen;

            // Load the custom app icon if available
            try { this.Icon = new Icon("PEinfoLogo.ico"); }
            catch { /* fail silently and keep default icon */ }

            BuildMainArea();
            BuildSidebar();
            BuildHeader();
            BuildStatusBar();

            ShowEmptyState(true);

            // Setup the main animation loop
            globalTimer = new System.Windows.Forms.Timer { Interval = 16 };
            globalTimer.Tick += (s, e) => {
                bool needsRedrawProgress = false;

                // Handle progress bar animation
                if (Math.Abs(currentProgress - progressTarget) > 0.05f)
                {
                    currentProgress += (progressTarget - currentProgress) * 0.15f;
                    needsRedrawProgress = true;
                }
                else if (currentProgress != (float)progressTarget)
                {
                    currentProgress = (float)progressTarget;
                    needsRedrawProgress = true;
                }

                // Handle navigation indicator sliding animation
                if (Math.Abs(navIndicatorCurrentY - navIndicatorTargetY) > 0.1f)
                {
                    navIndicatorCurrentY += (navIndicatorTargetY - navIndicatorCurrentY) * 0.2f;
                    if (navIndicator != null) navIndicator.Top = (int)navIndicatorCurrentY;
                }

                // Only redraw the progress bar if the value actually changed
                if (needsRedrawProgress) progressBarCustom?.Invalidate();
            };
            globalTimer.Start();
        }

        private void BuildSidebar()
        {
            sidePanel = new Panel { Dock = DockStyle.Left, Width = 230, BackColor = C_SIDEBAR };
            this.Controls.Add(sidePanel);

            navIndicator = new Panel { Width = 4, Height = 48, BackColor = C_ACCENT, Left = 0 };
            sidePanel.Controls.Add(navIndicator);
            navIndicator.BringToFront();

            btnStrings = CreateNavButton("Strings Explorer", "", 2);
            btnStrings.Click += (s, e) => Navigate(btnStrings, 2);
            sidePanel.Controls.Add(btnStrings);

            btnImports = CreateNavButton("Imports / Exports", "", 1);
            btnImports.Click += (s, e) => Navigate(btnImports, 1);
            sidePanel.Controls.Add(btnImports);

            btnDashboard = CreateNavButton("Dashboard", "", 0);
            btnDashboard.Click += (s, e) => Navigate(btnDashboard, 0);
            sidePanel.Controls.Add(btnDashboard);

            // Sidebar logo area
            var logoPnl = new Panel { Dock = DockStyle.Top, Height = 100 };
            logoPnl.Paint += (s, e) => {
                e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;

                try
                {
                    // Draw the custom icon
                    using var ico = new Icon("PEinfoLogo.ico");
                    e.Graphics.DrawIcon(ico, new Rectangle(18, 25, 46, 46));
                }
                catch
                {
                    // Fallback to a drawn circle if the icon is missing
                    using var br = new LinearGradientBrush(new Rectangle(25, 30, 35, 35), C_ACCENT, C_ACCENT2, 45f);
                    e.Graphics.FillEllipse(br, 25, 30, 35, 35);
                }

                e.Graphics.DrawString("PE DUMPER", new Font("Segoe UI", 11, FontStyle.Bold), new SolidBrush(C_TEXT), 72, 30);
                e.Graphics.DrawString("X-EDITION", new Font("Segoe UI", 7, FontStyle.Bold), new SolidBrush(C_ACCENT), 74, 48);
            };
            sidePanel.Controls.Add(logoPnl);

            SetActiveNav(btnDashboard);
        }

        private Button CreateNavButton(string t, string icon, int idx)
        {
            var b = new Button
            {
                Text = $"   {icon}   {t}",
                Dock = DockStyle.Top,
                Height = 48,
                FlatStyle = FlatStyle.Flat,
                TextAlign = ContentAlignment.MiddleLeft,
                ForeColor = C_TEXT_SEC,
                Font = new Font("Segoe MDL2 Assets", 11F),
                Cursor = Cursors.Hand
            };
            b.FlatAppearance.BorderSize = 0;
            return b;
        }

        private void Navigate(Button b, int idx)
        {
            SetActiveNav(b);
            if (tabMain != null) tabMain.SelectedIndex = idx;
        }

        private void SetActiveNav(Button b)
        {
            if (activeNavBtn != null) activeNavBtn.ForeColor = C_TEXT_SEC;
            activeNavBtn = b;
            b.ForeColor = C_ACCENT;
            navIndicatorTargetY = b.Top;
        }

        private void BuildHeader()
        {
            headerPanel = new Panel { Dock = DockStyle.Top, Height = 70, BackColor = C_SURFACE };
            this.Controls.Add(headerPanel);

            btnLoad = new Button
            {
                Text = "   LOAD FILE",
                Location = new Point(25, 17),
                Size = new Size(160, 38),
                FlatStyle = FlatStyle.Flat,
                BackColor = C_ACCENT,
                ForeColor = Color.White,
                Font = new Font("Segoe UI", 9, FontStyle.Bold),
                Cursor = Cursors.Hand
            };
            btnLoad.FlatAppearance.BorderSize = 0;
            btnLoad.Click += (s, e) => {
                using var ofd = new OpenFileDialog { Filter = "PE Binaries|*.exe;*.dll;*.sys" };
                if (ofd.ShowDialog() == DialogResult.OK) AnalyzeFile(ofd.FileName);
            };
            headerPanel.Controls.Add(btnLoad);

            progressBarCustom = new Panel { Dock = DockStyle.Bottom, Height = 2, BackColor = Color.FromArgb(40, 40, 45) };
            progressBarCustom.Paint += (s, e) => {
                if (currentProgress <= 0) return;
                float w = progressBarCustom.Width * (currentProgress / 100f);
                if (w < 1) w = 1;
                using var br = new LinearGradientBrush(new RectangleF(0, 0, w, 2), C_ACCENT, C_ACCENT2, 0f);
                e.Graphics.FillRectangle(br, 0, 0, w, 2);
            };
            headerPanel.Controls.Add(progressBarCustom);
        }

        private void BuildMainArea()
        {
            mainContainer = new Panel { Dock = DockStyle.Fill, BackColor = C_BG, Padding = new Padding(20) };
            this.Controls.Add(mainContainer);

            emptyState = new Panel { Dock = DockStyle.Fill, BackColor = C_BG };
            emptyState.Paint += (s, e) => {
                e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
                int cx = emptyState.Width / 2; int cy = emptyState.Height / 2;
                e.Graphics.DrawString("", new Font("Segoe MDL2 Assets", 40), new SolidBrush(C_CARD), cx - 35, cy - 80);
                e.Graphics.DrawString("DROP PE FILE HERE", new Font("Segoe UI", 14, FontStyle.Bold), new SolidBrush(C_BORDER), cx - 110, cy);
            };
            mainContainer.Controls.Add(emptyState);

            tabMain = new TabControl { Dock = DockStyle.Fill, Appearance = TabAppearance.FlatButtons, ItemSize = new Size(0, 1), SizeMode = TabSizeMode.Fixed };
            mainContainer.Controls.Add(tabMain);

            BuildDashboardTab();
            BuildImportsTab();
            BuildStringsTab();
        }

        private void BuildDashboardTab()
        {
            tabDashboard = new TabPage { BackColor = C_BG };
            tabMain!.TabPages.Add(tabDashboard);

            TableLayoutPanel layout = new TableLayoutPanel { Dock = DockStyle.Fill, RowCount = 2 };
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 30f));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 70f));
            tabDashboard.Controls.Add(layout);

            var infoCard = CreateCard(DockStyle.Fill, 0);
            txtInfo = new RichTextBox { Dock = DockStyle.Fill, BackColor = C_CARD, ForeColor = C_TEXT, BorderStyle = BorderStyle.None, Font = new Font("Consolas", 10), ReadOnly = true };
            infoCard.Controls.Add(txtInfo);
            infoCard.Controls.Add(MakeHeader("ANALYSIS OVERVIEW"));
            layout.Controls.Add(infoCard, 0, 0);

            var secCard = CreateCard(DockStyle.Fill, 0);
            gridSections = new DataGridView
            {
                Dock = DockStyle.Fill,
                BackgroundColor = C_CARD,
                BorderStyle = BorderStyle.None,
                RowHeadersVisible = false,
                AllowUserToAddRows = false,
                EnableHeadersVisualStyles = false,
                GridColor = C_BORDER,
                SelectionMode = DataGridViewSelectionMode.FullRowSelect
            };

            gridSections.ColumnHeadersDefaultCellStyle.BackColor = Color.FromArgb(45, 48, 65);
            gridSections.ColumnHeadersDefaultCellStyle.ForeColor = Color.White;
            gridSections.ColumnHeadersHeight = 40;

            gridSections.DefaultCellStyle.BackColor = C_CARD;
            gridSections.DefaultCellStyle.ForeColor = C_TEXT;
            gridSections.DefaultCellStyle.SelectionBackColor = Color.FromArgb(60, 65, 85);
            gridSections.DefaultCellStyle.SelectionForeColor = Color.White;

            gridSections.AlternatingRowsDefaultCellStyle.BackColor = Color.FromArgb(32, 33, 45);

            gridSections.Columns.Add("n", "NAME");
            gridSections.Columns.Add("vs", "VIRTUAL SIZE");
            gridSections.Columns.Add("rs", "RAW SIZE");
            gridSections.Columns.Add("va", "VIRTUAL ADDR");
            gridSections.Columns.Add(new DataGridViewTextBoxColumn { Name = "e", HeaderText = "ENTROPY", AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill });

            secCard.Controls.Add(gridSections);
            secCard.Controls.Add(MakeHeader("MEMORY SECTIONS"));
            layout.Controls.Add(secCard, 0, 1);
        }

        private void BuildImportsTab()
        {
            tabImports = new TabPage { BackColor = C_BG };
            tabMain!.TabPages.Add(tabImports);
            var split = new SplitContainer { Dock = DockStyle.Fill, SplitterWidth = 12 };
            tabImports.Controls.Add(split);

            var c1 = CreateCard(DockStyle.Fill, 0); split.Panel1.Controls.Add(c1);
            treeImports = new TreeView { Dock = DockStyle.Fill, BackColor = C_CARD, ForeColor = C_TEXT, BorderStyle = BorderStyle.None, LineColor = C_ACCENT };
            c1.Controls.Add(treeImports); c1.Controls.Add(MakeHeader("IMPORTS (IAT)"));

            var c2 = CreateCard(DockStyle.Fill, 0); split.Panel2.Controls.Add(c2);
            listExports = new ListView { Dock = DockStyle.Fill, BackColor = C_CARD, ForeColor = C_TEXT, BorderStyle = BorderStyle.None, View = View.Details, FullRowSelect = true };
            listExports.Columns.Add("EXPORT NAME", 450);
            c2.Controls.Add(listExports); c2.Controls.Add(MakeHeader("EXPORTS (EAT)"));
        }

        private void BuildStringsTab()
        {
            tabStrings = new TabPage { BackColor = C_BG };
            tabMain!.TabPages.Add(tabStrings);
            var card = CreateCard(DockStyle.Fill, 0); tabStrings.Controls.Add(card);
            listStrings = new ListView { Dock = DockStyle.Fill, BackColor = C_CARD, ForeColor = C_TEXT, BorderStyle = BorderStyle.None, View = View.Details, FullRowSelect = true };
            listStrings.Columns.Add("VALUE", 1000);
            card.Controls.Add(listStrings);
            var sBox = new Panel { Dock = DockStyle.Top, Height = 50, Padding = new Padding(15, 10, 15, 10) };
            txtSearchStrings = new TextBox { Dock = DockStyle.Fill, BackColor = C_BG, ForeColor = C_TEXT, BorderStyle = BorderStyle.FixedSingle, PlaceholderText = "Filter strings..." };
            txtSearchStrings.TextChanged += (s, e) => FilterStrings(txtSearchStrings.Text);
            sBox.Controls.Add(txtSearchStrings); card.Controls.Add(sBox);
            card.Controls.Add(MakeHeader("STRING SEARCH"));
        }

        private void BuildStatusBar()
        {
            statusStrip = new StatusStrip { BackColor = C_SIDEBAR, ForeColor = C_TEXT_SEC, SizingGrip = false };
            lblStatus = new ToolStripStatusLabel { Text = "IDLE", ForeColor = C_SUCCESS, Font = new Font("Segoe UI", 9, FontStyle.Bold) };
            lblFile = new ToolStripStatusLabel { Text = "Waiting...", Spring = true, TextAlign = ContentAlignment.MiddleRight };
            statusStrip.Items.Add(lblStatus); statusStrip.Items.Add(lblFile);
            this.Controls.Add(statusStrip);
        }

        private Panel CreateCard(DockStyle d, int h)
        {
            var p = new Panel { Dock = d, BackColor = C_CARD, Padding = new Padding(15) };
            if (h > 0) p.Height = h;
            p.Paint += (s, e) => e.Graphics.DrawRectangle(new Pen(C_BORDER), 0, 0, p.Width - 1, p.Height - 1);
            return p;
        }

        private Label MakeHeader(string t) => new Label { Text = t, Dock = DockStyle.Top, Height = 30, ForeColor = C_ACCENT, Font = new Font("Segoe UI", 8, FontStyle.Bold) };

        private void AnalyzeFile(string path)
        {
            try
            {
                ShowEmptyState(false);
                progressTarget = 30;
                lblStatus!.Text = "ANALYZING"; lblFile!.Text = System.IO.Path.GetFileName(path);

                var info = new PEAnalyzer().Analyze(path);
                currentStrings = info.Strings;
                progressTarget = 75;

                txtInfo!.Clear();
                FormatLine(txtInfo, "FILE:     ", info.FileName, C_ACCENT);
                FormatLine(txtInfo, "ARCH:     ", info.Architecture, C_TEXT);
                FormatLine(txtInfo, "ENTRY PT: ", $"0x{info.EntryPointRva:X8}", C_SUCCESS);
                FormatLine(txtInfo, "STATUS:   ", info.IsPotentiallyPacked ? "PACKED / CRYPTED" : "CLEAN", info.IsPotentiallyPacked ? C_DANGER : C_SUCCESS);

                gridSections?.Rows.Clear();
                foreach (var s in info.Sections)
                {
                    int r = gridSections!.Rows.Add(s.Name, $"0x{s.VirtualSize:X8}", $"0x{s.RawSize:X8}", $"0x{s.VirtualAddress:X8}", s.Entropy.ToString("F3"));
                    if (s.Entropy > 7.4) gridSections.Rows[r].DefaultCellStyle.ForeColor = C_DANGER;
                }

                treeImports?.Nodes.Clear();
                foreach (var dll in info.ImportedDlls)
                {
                    var n = treeImports!.Nodes.Add(dll.DllName); n.ForeColor = C_ACCENT;
                    foreach (var f in dll.Functions) n.Nodes.Add(f).ForeColor = C_TEXT;
                }

                listExports?.Items.Clear();
                foreach (var f in info.ExportedFunctions) listExports!.Items.Add(new ListViewItem(f));

                FilterStrings("");
                progressTarget = 100; lblStatus.Text = "COMPLETE";

                // Reset progress bar after 2 seconds
                var resetTimer = new System.Windows.Forms.Timer { Interval = 2000 };
                resetTimer.Tick += (s, e) => { progressTarget = 0; resetTimer.Stop(); resetTimer.Dispose(); };
                resetTimer.Start();

            }
            catch (Exception ex) { MessageBox.Show(ex.Message); progressTarget = 0; }
        }

        private void FormatLine(RichTextBox r, string head, string val, Color c)
        {
            r.SelectionStart = r.TextLength; r.SelectionColor = C_TEXT_SEC; r.AppendText(head);
            r.SelectionColor = c; r.AppendText(val + "\n");
        }

        private void FilterStrings(string q)
        {
            if (listStrings == null) return;
            listStrings.BeginUpdate(); listStrings.Items.Clear();
            foreach (var s in currentStrings.Where(x => x.Contains(q, StringComparison.OrdinalIgnoreCase)).Take(1500))
                listStrings.Items.Add(new ListViewItem(s));
            listStrings.EndUpdate();
        }

        private void ShowEmptyState(bool s) { if (emptyState != null) emptyState.Visible = s; if (tabMain != null) tabMain.Visible = !s; }
    }
}