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
         
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

           
            Application.Run(new MainForm());
        }
    }
}
