using System;
using System.Windows.Forms;
using PEInfoDumperx.UI;

namespace PEInfoDumperx
{
    static class Program
    {
        [STAThread]
        static void Main()
        {
            // Abilita gli stili visivi moderni per Windows 11 / 10
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            // Avvia la nuova interfaccia grafica!
            Application.Run(new MainForm());
        }
    }
}