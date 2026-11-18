// Device-specific syslog guides. Every device sends to the NovrSIEM collector of this installation (address and port
// come from the API). The sender must then be registered with the address NovrSIEM sees (its public address when it
// reaches us through NAT); NovrSOC verifies it before its events are accepted.

export interface Guide { id: string; label: string; vendor: string; deviceType: 'firewall' | 'router' | 'switch' | 'linux_server' | 'network_appliance' | 'other';
    steps: (t: { address: string; port: number }) => string[]; verify: string }

export const GUIDES: Guide[] = [
    {
        id: 'opnsense', label: 'OPNsense', vendor: 'OPNsense', deviceType: 'firewall',
        steps: (t) => [
            'Sign in to the OPNsense web interface as an administrator.',
            'Open System › Settings › Logging, then the Remote tab, and click + to add a destination.',
            'Enabled: on. Transport: UDP(4). Applications: leave empty to send everything (or choose filterlog, the firewall).',
            'Levels: info, notice, warning, error, critical, alert, emergency. Facilities: leave empty.',
            `Hostname: ${t.address}. Port: ${t.port}. RFC5424: on.`,
            'Save, then Apply.',
            'In Firewall › Rules, turn on "Log packets that are handled by this rule" for the rules you want to see.',
        ],
        verify: 'Status should change from "Awaiting NovrSOC verification" to "Receiving" a few minutes after NovrSOC verifies the sender.',
    },
    {
        id: 'firepower', label: 'Cisco Firepower (FTD managed by FMC)', vendor: 'Cisco', deviceType: 'firewall',
        steps: (t) => [
            'In the Firepower Management Center, open Devices › Platform Settings and edit the policy assigned to the device.',
            'Choose Syslog › Logging Setup: turn on Enable Logging and Send syslogs in EMBLEM format off.',
            `Syslog Servers › Add: IP address ${t.address}, protocol UDP, port ${t.port}, and the interface or security zone that reaches it.`,
            'Logging Destinations › Add: destination Syslog Servers, event class All Logs, severity Informational.',
            'In Policies › Access Control, edit the policy, open Logging and choose "Use the syslog settings configured in the FTD Platform Settings".',
            'On the access rules you want to see, turn on Log at End of Connection.',
            'Save and Deploy the changes to the device.',
        ],
        verify: 'Connection and threat events appear in Alerts once NovrSOC has verified the sender.',
    },
    {
        id: 'pfsense', label: 'pfSense', vendor: 'Netgate', deviceType: 'firewall',
        steps: (t) => [
            'Open Status › System Logs › Settings.',
            'Under Remote Logging Options, turn on Enable Remote Logging.',
            'Source Address: the interface that reaches NovrSOC. IP Protocol: IPv4.',
            `Remote log servers: ${t.address}:${t.port}.`,
            'Remote Syslog Contents: Everything (or Firewall Events at least). Save.',
        ],
        verify: 'Firewall events appear in Alerts once NovrSOC has verified the sender.',
    },
    {
        id: 'fortigate', label: 'FortiGate', vendor: 'Fortinet', deviceType: 'firewall',
        steps: (t) => [
            'Open the CLI console (or SSH) as an administrator.',
            `config log syslogd setting  ›  set status enable  ›  set server "${t.address}"  ›  set port ${t.port}  ›  set mode udp  ›  end`,
            'In Log & Report › Log Settings, confirm that forward traffic and security events are logged.',
        ],
        verify: 'Traffic and UTM events appear in Alerts once NovrSOC has verified the sender.',
    },
    {
        id: 'linux', label: 'Linux server (rsyslog)', vendor: 'Linux', deviceType: 'linux_server',
        steps: (t) => [
            'Create /etc/rsyslog.d/90-novrsoc.conf as root.',
            `Add one line: *.* @${t.address}:${t.port}   (one @ = UDP; @@ = TCP)`,
            'Restart rsyslog: sudo systemctl restart rsyslog',
            'For full endpoint visibility (files, processes, vulnerabilities), install NovrAgent instead or as well.',
        ],
        verify: 'Run logger "NovrSOC test" on the server; after verification the event reaches NovrSIEM.',
    },
    {
        id: 'generic', label: 'Other syslog device', vendor: '', deviceType: 'other',
        steps: (t) => [
            'Any device that sends standard syslog (RFC 3164 or RFC 5424) can be connected.',
            `Send to ${t.address}, port ${t.port}, over UDP (or TCP if the device supports it).`,
            'The device must always send from the same address: NovrSOC identifies the organization from it.',
        ],
        verify: 'Events appear in Alerts once NovrSOC has verified the sender.',
    },
];
