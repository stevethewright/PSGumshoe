<#
.SYNOPSIS
    Converts a raw Sysmon EventLogRecord into a structured PowerShell object.
.DESCRIPTION
    Takes a raw EventLogRecord object from the Sysmon event log and parses it into a structured PowerShell
    object with named properties. It maps the Event ID to a human-readable Sysmon event type and extracts
    all event data fields into a hashtable for easy access. The resulting object is tagged with a custom
    type name based on the Sysmon event type.
.EXAMPLE
    PS C:\> Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10 |
    >>     Where-Object { $_.Id -eq 1 } |
    >>     ConvertFrom-SysmonEventLogRecord
    Converts the latest 10 Sysmon process creation events into structured PowerShell objects.
.EXAMPLE
    PS C:\> $event = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 1
    PS C:\> $parsed = $event | ConvertFrom-SysmonEventLogRecord
    PS C:\> $parsed.EventType
    Retrieves the event type (e.g., "ProcessCreate") from a single Sysmon event.
.INPUTS
    System.Diagnostics.Eventing.Reader.EventLogRecord
#>
function ConvertFrom-SysmonEventLogRecord {
    [CmdletBinding()]
    param (
        # Event Log Record Object
        [Parameter(Mandatory = $true,
                   ValueFromPipeline = $true)]
        [System.Diagnostics.Eventing.Reader.EventLogRecord]
        $Event
    )
    begin {
        $EventIdtoType = @{
            '1' = 'ProcessCreate'
            '2' = 'FileCreateTime'
            '3' = 'NetworkConnect'
            '5' = 'ProcessTerminate'
            '6' = 'DriverLoad'
            '7' = 'ImageLoad'
            '8' = 'CreateRemoteThread'
            '9' = 'RawAccessRead'
            '10' = 'ProcessAccess'
            '11' = 'FileCreate'
            '12' = 'RegistryAddOrDelete'
            '13' = 'RegistryValueSet'
            '14' = 'RegistryRename'
            '15' = 'FileCreateStreamHash'
            '16' = 'ConfigChange'
            '17' = 'PipeCreated'
            '18' = 'PipeConnected'
            '19' = 'WmiFilter'
            '20' = 'WmiConsumer'
            '21' = 'WmiBinding'
            '22' = 'DNSQuery'
            '23' = 'FileDelete'
            '24' = 'ClipboardChange '
            '25' = 'ProcessTamper'
            '26' = 'FileDeleteDetected'
            '27' = 'FileBlockExecutable'
            '28' = 'FileBlockShredding'
            '29' = 'FileExecutableDetected'
            '255' = 'Error'
        }
    }

    process {
        [xml]$evtxml = $Event.toxml()
        $ProcInfo = [ordered]@{}
        $ProcInfo['EventId'] = $evtxml.Event.System.EventID
        $ProcInfo['EventType'] = "$($EventIdtoType[$([string]$evtxml.Event.System.EventID)] )"
        $ProcInfo['Computer'] = $evtxml.Event.System.Computer
        $ProcInfo['EventRecordID'] = $evtxml.Event.System.EventRecordID
        $evtxml.Event.EventData.Data | ForEach-Object {
            $ProcInfo[$_.name] = $_.'#text'
        }
        $Obj = New-Object psobject -Property $ProcInfo
        $Obj.pstypenames[0] = "Sysmon.EventRecord.$($EventIdtoType[$([string]$evtxml.Event.System.EventID)] )"
        $Obj
    }

    end {}
}