#
# Script to patch windows servers via powershell
# Created by hakon.brynildsen@nsm.stat.no 16.12.2014
#


$TmpDir = "c:\temp\"
$SchedName = "InstallUpdates_ScheduledTask_Powershell_Extravaganza"
$TmpFile = $TmpDir+$SchedName+".txt"

$Verbose = $False
$Debug = $False
[string]$Hostname = hostname
$UCHostname = $Hostname.ToUpper()
# $HowManyUpdatesThisRound = 0

if ($Verbose) {
  Write-Verbose "Verbose is set"
  $VerbosePreference = "continue"
}
if ($Debug) {
  Write-Debug "Debug is set"
  $DebugPreference = "continue"
}


# Check if the system is server 2012/windows 8 or higher. Else, do some magic
$Legacy = $false
$OSVersionRequirement = 6,2
if ( ( [System.Environment]::OSVersion.Version ) -lt (New-Object 'Version' $OSVersionRequirement) ) {
  $Legacy = $True
  Write-Host "This is a pre Server 2012 environment. Some functions are still in Beta."
} 


# Also check Powershell version
$PSVersionRequirement = "3.0"
if ( $PSVersionTable.PSVersion -lt $PSVersionRequirement ) {
  "Powershell version is " + $PSVersionTable.PSVersion
  "This script requires atleast " + $PSVersionRequirement
  "Manually update powershell and try again."

  exit 
}







# Purge the scheduledjob and Scheduledtask list.
# They have been known to persistantly remember deletet tasks
Get-ScheduledJob $SchedName -ErrorAction SilentlyContinue | Out-Null
if ( ! $Legacy) {
  Get-ScheduledTask $SchedName -ErrorAction SilentlyContinue | Out-Null
}



# Simple function to clean up the tmp file
Function CleanTempFile ([string]$myTmpFile = $TmpFile) {
  Write-Debug "Running CleanTempFile function"

  # Delete tmpfile
  if (Test-Path $TmpFile) {
    Get-ChildItem $TmpFile | Remove-Item
    Write-Debug "Attempted to run: `"Get-ChildItem $TmpFile | Remove-Item`"`nAttempt was..."
    if (Test-Path $TmpFile) {
      Write-Debug "FAILED. Try again or run manually"
    } else {
      Write-Debug "Successful"
    }
  }
}

# Simple function to delete ScheduledTask/ScheduledJob if exists
Function CleanScheduledTask ([string]$mySchedName = $SchedName) {
  Write-Debug "Running CleanScheduledTask function"

  # Delete Scheduledtask
  if ($Legacy) {
    $mySchedTask = Get-Job $SchedName -Newest 1 -ErrorAction SilentlyContinue
    # $mySchedTask = Get-ScheduledJob *$SchedName* -ErrorAction SilentlyContinue
  } else {
    $mySchedTask = Get-ScheduledTask *$SchedName*
  }
  if ( $mySchedTask ) {
    if ($mySchedTask.state -match "Running") {
      # SchedTask is running. This shouldnt happen, but I will not delete it now
      Write-Verbose "ScheduledTask $SchedName is running. I will not delete it until it's stopped."
    } else {
      Write-Verbose "Deleting SchedTask $SchedName"
      if ( ($mySchedTask | Measure-Object).Count -eq 1) {
        Write-Debug "Unregistering scheduledtask $SchedName"
        sleep 5
        Write-Debug "Deleting the schedtask. WHY?!?!?!"
        if ($legacy) {
          Get-ScheduledJob $SchedName | Unregister-ScheduledJob -Confirm:$False -ErrorAction SilentlyContinue
        } else {
          $mySchedTask | Unregister-ScheduledTask -Confirm:$False
        }
      } else {
        Write-Debug "There are more than one schedtask with that matches the search. Will not execute delete."
        Write-Verbose "Found" ($mySchedTask | Measure-Object).Count "scheduledtasks. Will not delete in case this is wrong."
      }
    }
  }
  
}


Function GetHash ([String]$myString) {
  $md5 = New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
  $utf8 = New-Object -TypeName System.Text.UTF8Encoding
  return [System.BitConverter]::ToString($md5.ComputeHash($utf8.GetBytes($myString)))
}


Function CheckRebootStatus ([bool]$ExitOnRestart=$true) {
  # Do not check for reboot status if the schedtask is running
  if ($Legacy) {
    $mySchedTask = Get-Job $SchedName -Newest 1 -ErrorAction SilentlyContinue
  } else {
    $mySchedTask = Get-ScheduledTask *$SchedName*
  }
  if ($mySchedTask.State -notmatch "Running") {
    if ( (Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' | Where-Object {$_.Name -match "RebootRequired"} | Measure-Object ).Count -gt 0 ) {
      Write-Host -ForegroundColor Red "System $UCHostname is requesting a reboot"
      $UserAnswer = Read-Host "Would you like to restart now (y/N)? "
      if ($UserAnswer.ToLower() -match "y") {
        CleanScheduledTask | Out-Null
        CleanTempFile | Out-Null
        (shutdown /r /t 0)
        Write-Host "Rebooting $UCHostname now..." | Out-Default
        exit
        sleep 1
      } else {
        Write-Host "Ok, then. Reboot at your leisure."
        if ($ExitOnRestart) {
          Write-Debug "In ExitOnRestart"
          Write-Verbose "In ExitOnRestart"
          Write-Host "Bye"
          exit
        } else {
          Write-Debug "In ExitOnRestart is FALSE"
          Write-Verbose "In ExitOnRestart is FALSE"
        }
      }
    } else {
      Write-Host "WindowsUpdate says 'No reboot required'"
     # CleanScheduledTask | Out-Null
     # CleanTempFile | Out-Null
    }
  }
}


Function GetUpdateStatus {
  # Return Update status
  # Return codes: 
  # 9999: Default code. 
  # 6666: ScheduledTask does not exists or is not running. TMP file exists.
  # 5555: Neither ScheduledTask nor tmp file exists
  # 0-1000: Number of patches to be installed
  # -1: No more patches available this round

  if ($Debug) {
    Write-Host ""
    Write-Debug "******************** CLS ******************************"
    Write-Host ""
  } else {
    cls
  }
  Write-Host $(Get-Date -UFormat %c )
  Write-Debug "Running GetUpdateStatus function"
  Write-Host "Running on" $UCHostname | Out-Default

  # Check status of ongoing update. Return number of updates still to install
  $ReturnValue = 9999
  $AllIsFinished = $False
  $NumberOfPatchesToBeInstalled = 0        
  $NumberOfPatchesThatHaveBeenInstalled = 0
  $MainUpdatedResult = ""
 
  If (Test-Path $TmpFile) {
    # Get the list of updates which are to be installed
    $TmpFileContents = Get-Content $TmpFile

    # Get the list of updates which have been installed
    $Session = New-Object -ComObject Microsoft.Update.Session
    $UpdateSearcher = $Session.CreateUpdateSearcher()
    $HistoryCount = $UpdateSearcher.GetTotalHistoryCount()

    # Before the updates have started, these variables will need some spoof values
    if ($HistoryCount -eq 0) {
      $HistoryCount = 999
      $MainUpdatedResult = 0
    }

    $UpdatedResult = $UpdateSearcher.QueryHistory(0,$HistoryCount)
    $MainUpdatedResult = $UpdatedResult  # Used for sanity checks later

    if ($false) {
     $SearchResult = $Searcher.Search($Criteria).Updates;
     $Criteria = "IsInstalled=0 and Type='Software'"
     $FindUpdates = New-Object -ComObject Microsoft.Update.Searcher
     $UpdatesAvailable = $FindUpdates.Search($Criteria).Updates
     $ReturnValue = ($UpdatesAvailable | Measure-Object).Count
     }

    # Run through and compare the lists to determine which have been installed and which have not
    $TmpFileContents | ForEach-Object {
      $PatchTitle = $_
      $UpdateIsFinished = $False

      # Some sanity checks. All updates contain a KB number. Example: KB1424232
      if ($PatchTitle -match  "\(KB\d{6,7}\)") {
        $NumberOfPatchesToBeInstalled ++

        $PatchTitle = ($PatchTitle -replace "\s*$", "") -replace "^\s*", ""
        $OutputString = $PatchTitle
        
        $HashOfPatchTitle = GetHash($PatchTitle)   # For easy string matching, use hash

        # Run through the installed patches and try to find $Patch. If exists, the patch has been installed.
        # If the schedtask is stopped then the install of that patch has failed or not completed.
        $UpdatedResult | ForEach-Object {

          $UpdateTitle = $_.Title
          $HashOfUpdateTitle = GetHash($UpdateTitle)  # For easy string matching, use hash

          $KBNumberFromUpdate = ($UpdateTitle -replace "^.*\(KB", "KB") -Replace "\).*$", ""
          if ($HashOfUpdateTitle -match $HashOfPatchTitle) {
            $OutputString = "Finished: " + $OutputString # + " (Windows ResultCode: " + $_.ResultCode + ")"

            if ($_.ResultCode -eq 1) {
              $NumberOfPatchesThatHaveBeenInstalled++      # Count how many updates that have been successfully installed
            }
            $UpdateIsFinished = $True
            Write-Host -ForegroundColor Green $OutputString | Out-Default
          } 
        }
        if ( -not $UpdateIsFinished ) {
          $OutputString = "In progress: " + $OutputString
          Write-Host -ForegroundColor Yellow $OutputString | Out-Default
        }
      }
    }
  } else {
    Write-Verbose "Tmpfile does not exist. Nothing to do."

    # Check if the updates are finished and if the machine requires reboot
    if ($Legacy) {
      $mySchedTask = Get-Job $SchedName -Newest 1 -ErrorAction SilentlyContinue
    } else{
      $mySchedTask = Get-ScheduledTask *$SchedName*
    }

    # Check if scheduled task is still running even if tmp file is missing.
    if ($mySchedTask.State -match "Running") {
      Write-Host "Update job is still running. However the tmp file has been removed."
      Write-Host "Cannot create updatestatus information"
      Write-Host "Fix: Recommend running this script again to regenerate tmp file"
    } else {
      Write-Host "Checking if reboot is required..."
      CheckRebootStatus
    }
    $ReturnValue = -1
  }

  # Check if the schedtask is still running
  if ($Legacy) {
    $mySchedTask = Get-Job $SchedName -Newest 1 -ErrorAction SilentlyContinue
  } else {
    $mySchedTask = Get-ScheduledTask *$SchedName*
  }

  # $b = $mySchedTask.State
  # Write-Host -ForegroundColor Cyan "------->$b"

  if ($mySchedTask.State -match "Running") {
    Write-Host "Update is still running on $UCHostname ($NumberOfPatchesThatHaveBeenInstalled of $NumberOfPatchesToBeInstalled finished), please wait..." | Out-Default ; sleep 1
    
    $ReturnValue = $NumberOfPatchesToBeInstalled - $NumberOfPatchesThatHaveBeenInstalled

    # Sanity check. If tmpfile is empty or missing
    if ( -not (Test-Path $TmpFile)) {
      Write-Host "Cannot find tmpfile. Will try to recreate it."
      CheckForUpdates | Out-Null
    }
  } elseif ($mySchedTask.State -match "Ready" -or $mySchedTask.State -match "Completed" ) {
    # Get-ScheduledTask will return "Ready". Get-ScheduledJobs will return "Completed"
    Write-Host "Update is finished. Doing some sanity checks of the results, please wait..."
    Write-Debug "Checking if reboot is required"
    Write-Host "Before"
    CheckRebootStatus | Out-Default
    Write-Host "after"
    $ReturnValue = -1
  } else {
    # Schedtask does not exist or is not running. Check if tmp file exists
    Write-Debug "Debug stamp 14"
    Write-Verbose "SchedTask $SchedName does not exist or is not running on $(hostname)"
    if (Test-Path $TmpFile) {
      CleanTempFile | Out-Null
      $ReturnValue = 6666
    } else {  
      $ReturnValue = 5555
    }
  }

  Return $ReturnValue
}


Function CheckForUpdates {
  # Run Check to see if there are any updates available
  # If updates are available, write a temp file for reference later
  
  Write-Debug "Running CheckForUpdates function"
  Write-Host "Checking for available updates. Please wait..."

  $ReturnValue = 0
  
  $Criteria = "IsInstalled=0 and Type='Software'"
  $FindUpdates = New-Object -ComObject Microsoft.Update.Searcher
  $UpdatesAvailable = $FindUpdates.Search($Criteria).Updates
  $ReturnValue = ($UpdatesAvailable | Measure-Object).Count
  

  Write-Debug "ReturnValue from UpdatesAvailable is: $ReturnValue"

  if ( ! (Test-Path $TmpDir ) ) {
    Write-Verbose "Creating new TMP Directory: $TmpDir"
    New-Item -ItemType Directory $TmpDir | Out-Null
  }  

  if ( ! (Test-Path $TmpFile )) {
    Write-Verbose "Verbose: Creating TEMPfile: $TmpFile"
    New-Item -ItemType File $TmpFile | Out-Null
  }

  if ( Test-Path $TmpFile ) {
    Write-Verbose "Setting content to tmpfile..."
    $UpdatesAvailable | select Title | Out-File -Encoding UTF8 $TmpFile
  }

  if ( $ReturnValue -gt 0 ) {
    # Write-Debug "`n"
    Write-Host "Found $ReturnValue updates to download and install on $UCHostname."
    " "
    $UpdatesAvailable | ForEach-Object {
      $Title = $_.Title
      $KBNumber = ($_.Title -split '.*\((?<KB>KB\d{6,7})\)')[1]
      
      Write-Host " $KBNumber : $Title"
    }
  }
  Return $ReturnValue
}


Function DoInstall {
  Write-Debug "Running DoInstall function"
  $UserAnswer = Read-Host "Do you wish to [Q]uit or Download and [I]nstall? (Default: Quit)"
      
  if ($UserAnswer.ToLower() -match "i") {
    Write-Debug "Registering ScheduledTask name : $SchedName"
    "Registering ScheduledTask..."
    $myScheduledJobsOption = New-ScheduledJobOption -RunElevated:$true
    # Register-ScheduledJob -Name $SchedName -RunNow -ScheduledJobOption $myScheduledJobsOption -ScriptBlock {
    Register-ScheduledJob -Name $SchedName -ScriptBlock {

      $Criteria = "IsInstalled=0 and Type='Software'"
      $Searcher = New-Object -ComObject Microsoft.Update.Searcher
   
      $SearchResult = $Searcher.Search($Criteria).Updates
    
      $Count = ($SearchResult |measure-object).Count

      $Session = New-Object -ComObject Microsoft.Update.Session;
 
      ## Start download of updates
      # Note: Does it download if already downloaded?
      $Downloader = $Session.CreateUpdateDownloader();
      $Downloader.Updates = $SearchResult;
      $Downloader.Download();

      ## Do the install of the patches
      $Installer = New-Object -ComObject Microsoft.Update.Installer;
      $Installer.Updates = $SearchResult;
      $Result = $Installer.Install();
    } | Out-Null 
    # End schedjob
    "Done registering scheduledtask"

    # If user asked for it, start install
    Write-Host "Starting Download/Install job. Please wait..."
    # "Pro tip: You can run this script again to check status."
    if ($Legacy) {
      Write-Debug "STARTING $SchedName"
      
      $myScheduledJobsOption = New-ScheduledJobOption -RunElevated:$true
      Get-ScheduledJob -Name $SchedName | Set-ScheduledJob -RunNow -ScheduledJobOption $myScheduledJobsOption

      # (schtasks.exe /run /tn \microsoft\windows\powershell\scheduledjobs\$SchedName)
      if ($Debug) {
        Get-Job
      }

      Write-Verbose "Legacy: Has started $SchedName"
      sleep 5 | Out-Null
      Get-Job
    } else {
      Get-ScheduledTask -TaskName *$SchedName* | Start-ScheduledTask
      Write -Verbose "Has started $SchedName"
      sleep 5 | Out-Null
    }
  } else {
    "Update cancelled by user."
    CleanTempfile
    CleanScheduledTask

    exit
  }
}



# First of all: Check if an update is running, if not check for updates.
if ($Legacy) {
  # $RunningScheduledTask = Get-Job $SchedName -newest 1 -ErrorAction SilentlyContinue|Where-Object {$_.State -match "Running"}
  $RunningScheduledTask = $False
  $TrustedInstaller = Get-Process TrustedInstaller -ErrorAction SilentlyContinue
  if ($TrustedInstaller) {
    if ( ((Get-Counter "\Process(TrustedInstaller)\% Processor Time").CounterSamples).CookedValue -gt 10) {
      $RunningScheduledTask = $True
    }
  }
  # $RunningScheduledTask = ((Get-Process TrustedInstaller).cpu -gt 100)
} else {
  $RunningScheduledTask = Get-ScheduledTask *$SchedName* |Where-Object {$_.State -match "Running"}
}
if ($RunningScheduledTask) {
  Write-Debug "Found ScheduledTask $SchedName. Will continue."
  # Update is already running. Just continue.
} else {
  # Update is not running. Start one.
  Write-Debug "Update is not running. Do some cleanup to be absolutely safe."
  CleanTempfile | Out-Null
  CleanScheduledTask | Out-Null

  Write-Debug "Update is not running. Start one"
  Write-Verbose "Update is not running. Start one"

  # Check if machine is pending a reboot before continuing
  Write-Debug "Checking if machine is requesting a reboot before starting..."
  if ( (Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' | Where-Object {$_.Name -match "RebootRequired"} | Measure-Object ).Count -gt 0 ) {
    Write-Host "Check if previous updates are pending a system reboot..."
    CheckRebootStatus($False)
      Write-Host -ForegroundColor Magenta "You may continue, but new updates might not install before reboot is completed."
      $UserAnswer = Read-Host "Do you wish to try to continue with updates (y/N)"
      if ($UserAnswer.ToLower() -match "y") {
        # Do nothing
      } else {
        CleanTempfile | Out-Null
        CleanScheduledTask | Out-Null
        exit
      }
    #}
  } else {
    # Nothing to. Can delete this else
  }

  $NumberOfUpdates = CheckForUpdates
  Write-Debug "NumberOfUpdates is  -----> $NumberOfUpdates"

  if ($NumberOfUpdates -gt 0) {
    DoInstall
  } else {
    Write-Host -ForegroundColor Green "There are no new updates to install on $UCHostname"
    CheckRebootStatus

    Write-Host "Bye`n"
    exit
  }
}







# Main runloop
$KeepOnTrucking = $True
$AllowRunASecondTime = $True
while ($KeepOnTrucking) {
  if (! $Debug) {
    Clear-Host
  }

  Write-Host  " " | Out-Default 
  ($RunningUpdateStatus = GetUpdateStatus) | Out-Null
  
  Write-Debug "Returnvalue of GetUpdateStatus: $RunningUpdateStatus" | Out-Default
  
  Switch ($RunningUpdateStatus) {
    9999 { 
      Write-Debug "9999 is the number"
      Write-Verbose "GetUpdateStatus returned 9999"
      $KeepOnTrucking = $False
    }
    5555 { 
      Write-Host -ForegroundColor Red "The Scheduled Task" $SchedName "cannot be found. Something went wrong.`n"
      Write-Host -ForegroundColor Red "Either the SchedTask exists, but not the tmp file or vica versa."
      Write-Host "
Will attempt to tidy up and re-run, please wait...
If this situation continues, CTRL-c out of the program and do the following on host" $(Hostname) " :
 * Delete " $TmpFile " 
   (rm " $TmpFile ")
 * Delete ScheduledTask " $SchedName " 
   (Unregister-ScheduledTask" $SchedName ")`n"

      Write-Debug "5555 is the number"
      Write-Host  "5555 is the number"

      # Clean up
      CleanTempfile | Out-Null
      CleanScheduledTask | Out-Null

      if ( $AllowRunASecondTime ) {
        $AllowRunASecondTime=$False
        $KeepOnTrucking = $True
        Write-Host "Running again"

        $RunningUpdateStatus = GetUpdateStatus
      } else {
        $KeepOnTrucking = $False
        Write-Host "Will exit"
      }

    }
      -1 { 
      Write-Debug "-1 is the number"
      $KeepOnTrucking = $False

      # Run a test to see if there are more updates available
      Write-Host -ForegroundColor Green "Update script has finished on $UCHostname"
      Write-Host " " | Out-Default
      sleep 1

      CheckRebootStatus | Out-Default

      Write-Host "You should re-run this script to check for additional updates"
      Write-Host " "
    }
    default {
      $RunningUpdateStatus = GetUpdateStatus
    } 
  }
}


if ($RunningUpdateStatus -gt 6000) {
  Write-Debug "RunningUpdateStatus is GT 6000"
}

