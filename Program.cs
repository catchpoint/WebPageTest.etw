using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace wpt_etw
{
    class Program
    {
        static string[] IEEvents = {
            "Mshtml_CWindow_SuperNavigate2/Start",
            "Mshtml_BFCache",
            "Mshtml_WebOCEvents_BeforeNavigate",
            "Mshtml_CDoc_Navigation",
            "Mshtml_WebOCEvents_DOMContentLoaded",
            "Mshtml_WebOCEvents_DocumentComplete",
            "Mshtml_WebOCEvents_NavigateComplete",
            "Mshtml_CMarkup_LoadEvent_Start/Start",
            "Mshtml_CMarkup_LoadEvent_Stop/Stop",
            "Mshtml_CMarkup_DOMContentLoadedEvent_Start/Start",
            "Mshtml_CMarkup_DOMContentLoadedEvent_Stop/Stop"};
        static string[] WinInetEvents = {
            "WININET_DNS_QUERY/Start",
            "WININET_DNS_QUERY/Stop",
            "Wininet_Getaddrinfo/Start",
            "Wininet_Getaddrinfo/Stop",
            "Wininet_SocketConnect/Start",
            "Wininet_SocketConnect/Stop",
            "WININET_TCP_CONNECTION/Start",
            "WININET_TCP_CONNECTION/Stop",
            "WININET_TCP_CONNECTION/Fail",
            "Wininet_Connect/Stop",
            "WININET_HTTPS_NEGOTIATION/Start",
            "WININET_HTTPS_NEGOTIATION/Stop",
            "WININET_REQUEST_HEADER",
            "WININET_RESPONSE_HEADER",
            "Wininet_SendRequest/Start",
            "Wininet_SendRequest/Stop",
            "Wininet_SendRequest_Main",
            "Wininet_ReadData",
            "Wininet_UsageLogRequest",
            "Wininet_LookupConnection/Stop",
            "WININET_STREAM_DATA_INDICATED"
        };
        static TraceEventSession session;
        static bool must_exit = false;
        private static Mutex mutex = new Mutex();
        static string events = "";


        static void Main()
        {
            // create a real time user mode session
            using (session = new TraceEventSession("wpt-etw"))
            {
                session.StopOnDispose = true;
                // Set up Ctrl-C to stop the session
                Console.CancelKeyPress += (object s, ConsoleCancelEventArgs args) => session.Stop();

                session.Source.Dynamic.All += delegate (TraceEvent data)
                {
                    bool keep = false;
                    if (data.ProviderName == "Microsoft-IE" &&
                        IEEvents.Contains(data.EventName))
                    {
                        keep = true;
                    }
                    else if (data.ProviderName == "Microsoft-Windows-WinINet" &&
                             WinInetEvents.Contains(data.EventName))
                    {
                        keep = true;
                    }

                    if (keep)
                    {
                        Dictionary<string, dynamic> evt = new Dictionary<string, dynamic>();
                        evt["Provider"] = data.ProviderName;
                        evt["Event"] = data.EventName;
                        evt["ts"] = data.TimeStampRelativeMSec;
                        if (data.ActivityID != Guid.Empty)
                            evt["Activity"] = data.ActivityID;
                        if (data.RelatedActivityID != Guid.Empty)
                            evt["RelatedActivity"] = data.RelatedActivityID;
                        if (data.ProcessID >= 0)
                            evt["pid"] = data.ProcessID;
                        if (data.ThreadID >= 0)
                            evt["tid"] = data.ThreadID;
                        if (data.PayloadNames.Count() > 0)
                        {
                            Dictionary<string, dynamic> values = new Dictionary<string, dynamic>();
                            foreach (string name in data.PayloadNames)
                            {
                                values[name] = data.PayloadByName(name);
                            }
                            // Special-case a few events where teh default decoder doesn't work correctly
                            if (data.ProviderName == "Microsoft-Windows-WinINet")
                            {
                                ExtractWinInetValues(data, ref values);
                            }
                            evt["data"] = values;
                        }

                        //evt["ascii"] = System.Text.Encoding.ASCII.GetString(data.EventData());
                        //evt["raw"] = data.EventData();
                        string json = JsonConvert.SerializeObject(evt) + "\n";
                        mutex.WaitOne();
                        events += json;
                        mutex.ReleaseMutex();
                        //Debug.WriteLine(json);
                        //Console.WriteLine(json);
                    }
                };

                session.EnableProvider("Microsoft-IE", TraceEventLevel.Informational, 0x30801308);
                session.EnableProvider("Microsoft-Windows-WinINet");

                must_exit = false;
                var thread = new Thread(ThreadProc);
                thread.Start();
                session.Source.Process();   // Listen (forever) for events
                must_exit = true;
                thread.Join();
            }
        }

        private static void ThreadProc()
        {
            string done_file = AppDomain.CurrentDomain.BaseDirectory + "wpt-etw.done";
            Console.WriteLine("Forwarding ETW events to http://127.0.0.1:8888/");
            Console.WriteLine("To exit, hit ctrl-C or create the file " + done_file);
            int count = 0;
            HttpClient wptagent = new HttpClient();
            var content = new StringContent("wptagent.started", Encoding.UTF8, "application/json");
            wptagent.PostAsync("http://127.0.0.1:8888/etw", content);
            do
            {
                Thread.Sleep(100);
                string buff = "";
                mutex.WaitOne();
                if (events.Length > 0)
                {
                    buff = events;
                    events = "";
                }
                mutex.ReleaseMutex();

                if (buff.Length > 0)
                {
                    content = new StringContent(buff, Encoding.UTF8, "application/json");
                    wptagent.PostAsync("http://127.0.0.1:8888/etw", content);
                }

                // Check to see if we need to exit every 1 second (10 loops through)
                count++;
                if (count >= 10)
                {
                    if (File.Exists(done_file))
                    {
                        try
                        {
                            File.Delete(done_file);
                        }
                        catch
                        {
                        }
                        must_exit = true;
                    }
                    count = 0;
                }
            } while (!must_exit);
            Console.WriteLine("Exiting...");
            session.Stop();
        }

        /*
         * Handle messages that the underlying library doesn't handle correctly (mostly ASCII strings)
         **/
        static void ExtractWinInetValues(TraceEvent data, ref Dictionary<string, dynamic> values)
        {
            if (data.EventName == "WININET_REQUEST_HEADER" || data.EventName == "WININET_RESPONSE_HEADER")
            {
                byte[] raw = data.EventData().Skip(10).ToArray();
                values["Headers"] = System.Text.Encoding.ASCII.GetString(raw);
            }
            else if (data.EventName == "WININET_DNS_QUERY/Start")
            {
                byte[] raw = data.EventData().Skip(2).ToArray();
                int count = 0;
                foreach (byte c in raw)
                {
                    if (c == 0)
                        break;
                    count++;
                }
                values["HostName"] = System.Text.Encoding.ASCII.GetString(raw.Take(count).ToArray());
            }
            else if (data.EventName == "WININET_DNS_QUERY/Stop")
            {
                byte[] raw = data.EventData().Skip(2).ToArray();
                int count = 0;
                foreach (byte c in raw)
                {
                    if (c == 0)
                        break;
                    count++;
                }
                values["HostName"] = System.Text.Encoding.ASCII.GetString(raw.Take(count).ToArray());
                // Find the beginning of the address list (numerical characters)
                raw = raw.Skip(count).ToArray();
                count = 0;
                foreach (byte c in raw)
                {
                    if (c >= '0' && c <= '9')
                        break;
                    count++;
                }
                raw = raw.Skip(count).ToArray();
                values["AddressList"] = System.Text.Encoding.ASCII.GetString(raw);
            }
            else if (data.EventName == "WININET_TCP_CONNECTION/Start")
            {
                byte[] raw = data.EventData().Skip(2).ToArray();
                int count = 0;
                foreach (byte c in raw)
                {
                    if (c == 0)
                        break;
                    count++;
                }
                values["ServerName"] = System.Text.Encoding.ASCII.GetString(raw.Take(count).ToArray());
            }
            else if (data.EventName == "Wininet_SendRequest/Stop")
            {
                byte[] raw = data.EventData().Reverse().ToArray();
                int count = 0;
                foreach (byte c in raw)
                {
                    if (c == 0)
                        break;
                    count++;
                }
                raw = raw.Take(count).Reverse().ToArray();
                values["StatusLine"] = System.Text.Encoding.ASCII.GetString(raw);
            }
            else if (data.EventName == "Wininet_Connect/Stop")
            {
                byte[] raw = data.EventData();
                values["LocalAddress"] = String.Format("{0}.{1}.{2}.{3}", values["LocalAddress"][4], values["LocalAddress"][5], values["LocalAddress"][6], values["LocalAddress"][7]);
                values["RemoteAddress"] = String.Format("{0}.{1}.{2}.{3}", values["RemoteAddress"][4], values["RemoteAddress"][5], values["RemoteAddress"][6], values["RemoteAddress"][7]);
            }
        }
    }
}
