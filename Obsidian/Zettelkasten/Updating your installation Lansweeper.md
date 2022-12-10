		{{date:YYYYMMDD}}/{{time:HHmm}}

		Status:#idea
		
		Tags:

		# {{title}}

It is recommended that you update your Lansweeper installation on a regular basis, to ensure that you have the latest available patches installed and access to any new features that have been released. You can [verify whether you have the latest Lansweeper version](https://community.lansweeper.com/t5/lansweeper-maintenance/checking-for-lansweeper-updates/ta-p/64339) from the web console and perform an update of a medium sized network in just a few minutes. Updates are free to anyone with an active Lansweeper license. They are installed over your existing installation and leave your existing data and settings intact. Reinstalling is not required in order to update.

Lansweeper 4.0 and any more recent Lansweeper releases can safely be updated to the latest Lansweeper version. Updates of older releases (1.x, 2.x or 3.x) are not supported. If you have a 1.x, 2.x or 3.x Lansweeper release, archive your installation for future reference and perform a new installation of the latest Lansweeper version instead.

Lansweeper installations hosted in the deprecated SQL Compact database server can no longer be updated to the latest Lansweeper version. To streamline future development, SQL Compact was phased out as a database server option. If you are still using SQL Compact as your database server, you should convert your database to SQL LocalDB or SQL Server. Afterward, you can update to the latest Lansweeper release.

## How to update your Lansweeper installation

1.  Make sure all computers hosting the scanning service or web console component have .NET Framework 4.8 or a more recent .NET version installed. This is a requirement from Lansweeper 8.2.200 onward. If you?re not sure which machines are hosting the Lansweeper service, you can find them listed in the Current Version section of this console page: `Configuration\Your Lansweeper License`
    
    If you run the Lansweeper installer version 8.2.200 or newer on a system that does not have .NET 4.8 or newer installed, the Lansweeper update will pause and install .NET 4.8 automatically. Updating your framework often requires a reboot, if you receive a reboot message at the end of the Lansweeper installer, you must reboot to ensure your Lansweeper components are functional.
    
    ![updating-your-installation-1.jpg](https://community.lansweeper.com/t5/image/serverpage/image-id/1114iCDD4F3B758F2320A/image-size/large/strip-exif-data/true?v=v2&px=999 "updating-your-installation-1.jpg")
    
    ![updating-your-installation-5.jpg](https://community.lansweeper.com/t5/image/serverpage/image-id/1115i25DEAD1BC96349FF/image-size/large/strip-exif-data/true?v=v2&px=999 "updating-your-installation-5.jpg")
    
2.  [Back up](https://community.lansweeper.com/t5/lansweeper-maintenance/backing-up-your-installation/ta-p/64309) your installation, to be safe.
3.  **Download** [the latest Lansweeper installer](https://www.lansweeper.com/update-lansweeper/) **and run it on a machine hosting the Lansweeper Server service.**
    
    If your Lansweeper database is hosted on a different machine than the Lansweeper service, running the installer on the machine hosting your database is not required. The Lansweeper service will automatically update your database.
    
4.  Hit the Next button, review the terms of use, which must be accepted to proceed.
    
    ![procedure-accepting-license-agreement-radiobutton.jpg](https://community.lansweeper.com/t5/image/serverpage/image-id/989i79ED9AE70EBF7C5D/image-size/large/strip-exif-data/true?v=v2&px=999 "procedure-accepting-license-agreement-radiobutton.jpg")
    
5.  Select the `Upgrade` option and hit Next. If the Upgrade option is grayed out, that either means that you are not running the latest installer or that you are already using the latest Lansweeper version. If this is the case, you should not proceed further and you should hit Cancel to close the installer instead.
    
    ![updating-your-installation-2.jpg](https://community.lansweeper.com/t5/image/serverpage/image-id/1116i7BB9E9F3AC2DE87B/image-size/large/strip-exif-data/true?v=v2&px=999 "updating-your-installation-2.jpg")
    
6.  The installer will automatically detect the Lansweeper components that require updating. Hit Next to continue.
    
    ![updating-your-installation-3.jpg](https://community.lansweeper.com/t5/image/serverpage/image-id/1117iFE4829C51CD6A0AA/image-size/large/strip-exif-data/true?v=v2&px=999 "updating-your-installation-3.jpg")
    
    If your database is hosted in an Express edition of Microsoft SQL Server and there is less than 300MB of free space, the installer will clear the database tables that store Windows event log data, to make room for the update. The Windows event log tables are usually the biggest. Express editions of old SQL Server versions are limited to 4GB by Microsoft, while Express editions of newer SQL Server versions (2008 R2 and beyond) are limited to 10GB.
    
7.  You will see your files being updated. The installer will automatically update the Lansweeper service, the Lansweeper database and, if it?s hosted on the same machine, the Lansweeper web console. How long the update takes depends on the size of your database.
    
    ![updating-your-installation-4.jpg](https://community.lansweeper.com/t5/image/serverpage/image-id/1118i27E2842CF6A042E7/image-size/large/strip-exif-data/true?v=v2&px=999 "updating-your-installation-4.jpg")
    
8.  When you get to the screen that confirms the successful update of your Lansweeper installation, hit `Finish` to close the installer.
    
    ![procedure-finishing-installer.jpg](https://community.lansweeper.com/t5/image/serverpage/image-id/992iCDDEF941289F9C52/image-size/large/strip-exif-data/true?v=v2&px=999 "procedure-finishing-installer.jpg")
    
9.  **If your Lansweeper web console is hosted on a different machine than the Lansweeper service, you will need to run the Lansweeper installer on that machine as well** and once again go through the update procedure.
10.  **If the Lansweeper service is hosted on multiple machines, which are all connected to your Lansweeper database, you will either need to run the installer on each machine hosting the service** and go through the update procedure each time **or use the available installer parameters to** [silently update the remaining scanning servers at once](https://community.lansweeper.com/t5/lansweeper-maintenance/silently-updating-remote-scanning-servers/ta-p/64340).
11.  If you are scanning Windows computers with the LsPush scanning agent, copy the up-to-date LsPush to any folder referenced by your logon script, group policy or scheduled task. After your Lansweeper update, the latest LsPush executable can be found in the following folder on your Lansweeper server:
    
    `Program Files (x86)\Lansweeper\Client`
    
12.  If you are scanning non-Windows computers with the LsAgent scanning agent, update the LsAgent installations on those machines as well, as they do not auto-update. The latest LsAgent installers can be downloaded through [this page](https://www.lansweeper.com/download/lsagent/).

		--
		# References
		