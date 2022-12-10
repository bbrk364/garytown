		{{date:YYYYMMDD}}/{{time:HHmm}}

		Status:#idea
		
		Tags:

		# {{Backing up your installation Lansweeper}}

**It is recommended that you back up your installation on a regular basis, especially prior to performing Lansweeper updates.** An unexpected shutdown of your Lansweeper server could lead to an update failure and subsequent database corruption. A manual backup is also required to move your installation from one server to another. Which backup procedure you should follow depends on which database server you are using. Lansweeper data, reports and settings are stored in a database. Your database is hosted in either the Microsoft SQL LocalDB, Microsoft SQL Server or (deprecated) Microsoft SQL Compact database server. You can [verify which database server you are using](https://community.lansweeper.com/t5/lansweeper-maintenance/identify-which-database-server-lansweeper-is-using/ta-p/64506) with the ConfigEditor tool or in the Lansweeper web console.

![procedure-checking-database-server.jpg](https://community.lansweeper.com/t5/image/serverpage/image-id/819i5D5FA19E97DB6F21/image-size/large/strip-exif-data/true?v=v2&px=999 "procedure-checking-database-server.jpg")

## Backing up if you are using SQL Compact

To back up your installation if you are using the deprecated SQL Compact database server, do the following:

1.  **Stop the Lansweeper Server service** in **Windows Services**
    
    ![procedure-stopping-the-lansweeper-service.jpg](https://community.lansweeper.com/t5/image/serverpage/image-id/921i01D324ECBAE5CC7B/image-size/large/strip-exif-data/true?v=v2&px=999 "procedure-stopping-the-lansweeper-service.jpg")
    
2.  **Stop your web server service** in **Windows Services**. Keep in mind that this will log everyone out of the console. Your web server service is either IIS Express or World Wide Web Publishing Service (IIS).
    
    ![procedure-stopping-the-web-server-service.jpg](https://community.lansweeper.com/t5/image/serverpage/image-id/904iA9794A9916C34312/image-size/large/strip-exif-data/true?v=v2&px=999 "procedure-stopping-the-web-server-service.jpg")
    
3.  **Create a copy of your SQL Compact database file**, which is:
    
    Program Files (x86)\Lansweeper\SQLData\lansweeperdb.sdf
    
4.  **If you added any documents, images, widgets or other files to Lansweeper, back these up as well.** Information on which folders store which files can be found in [this knowledge base article](https://community.lansweeper.com/t5/lansweeper-maintenance/where-lansweeper-data-reports-and-settings-are-stored/ta-p/64398#heading2 "Where lansweeper data reports and settings are stored").
    
    ![lightbulb.png](https://community.lansweeper.com/t5/image/serverpage/image-id/770i739C3FE407B8959A/image-size/large/strip-exif-data/true?v=v2&px=999 "lightbulb.png") Do not back up the entire Website folder. Only back up the specific subfolders, you need. Backing up and restoring the entire Website folder can lead to issues.
    
5.  **If it exists, create a backup copy of the following file** as well:
    
    Program Files (x86)\Lansweeper\Key\Encryption.txt
    
6.  **Restart the Lansweeper and web server services** in Windows Services.
    
    ![lightbulb.png](https://community.lansweeper.com/t5/image/serverpage/image-id/770i739C3FE407B8959A/image-size/large/strip-exif-data/true?v=v2&px=999 "lightbulb.png") SQL Compact was an old database server option that is no longer supported. If you are still using SQL Compact as your Lansweeper database server, you should [convert your database to SQL LocalDB or SQL Server](https://community.lansweeper.com/t5/lansweeper-maintenance/converting-a-deprecated-sql-compact-database/ta-p/64509).
    

## Backing up if you are using SQL LocalDB or SQL Server

To back up your installation if your database server is SQL LocalDB or SQL Server, do the following:

1.  **Stop the Lansweeper Server service** in **Windows Services**. Though creating a database backup while the scanning service is running may technically work, we recommend, as a best practice, not having anything connected to the database while you're running backup operations on it.
    
    ![procedure-stopping-the-lansweeper-service.jpg](https://community.lansweeper.com/t5/image/serverpage/image-id/921i01D324ECBAE5CC7B/image-size/large/strip-exif-data/true?v=v2&px=999 "procedure-stopping-the-lansweeper-service.jpg")
    
2.  **Stop your web server service** in **Windows Services**. Keep in mind that this will log everyone out of the console. Your web server service is either IIS Express or World Wide Web Publishing Service (IIS).
    
    ![procedure-stopping-the-web-server-service.jpg](https://community.lansweeper.com/t5/image/serverpage/image-id/904iA9794A9916C34312/image-size/large/strip-exif-data/true?v=v2&px=999 "procedure-stopping-the-web-server-service.jpg")
    
3.  **Log into SQL Server Management Studio.** If SQL Server Management Studio isn?t installed on your Lansweeper server, we recommend downloading it online.
    
    ![lightbulb.png](https://community.lansweeper.com/t5/image/serverpage/image-id/770i739C3FE407B8959A/image-size/large/strip-exif-data/true?v=v2&px=999 "lightbulb.png") If your database is hosted in SQL LocalDB, the SQL instance name you need to submit in Management Studio is (localdb)\.\LSInstance and you can log in with the Windows user that initially installed Lansweeper. If your database is hosted in SQL Server, you would have configured your SQL instance name and password when you installed SQL Server.
    
4.  **Right-click the** lansweeperdb **database and select Tasks\Back Up...** to open the backup wizard.
    
    ![backing-up-your-installation-1.jpg](https://community.lansweeper.com/t5/image/serverpage/image-id/945i1713FDC0DA5B9BA4/image-size/large/strip-exif-data/true?v=v2&px=999 "backing-up-your-installation-1.jpg")
    
    ![lightbulb.png](https://community.lansweeper.com/t5/image/serverpage/image-id/770i739C3FE407B8959A/image-size/large/strip-exif-data/true?v=v2&px=999 "lightbulb.png") Scanned data, reports, and settings are stored in your database. Scanning servers, which only run the Lansweeper Server service, don't store any data or settings. They retrieve settings from the database and send scanned data directly to the database.
    
5.  In the **General** tab of the backup wizard, **configure the source and destination options.** By default, the backup destination is a .bak file on your disk drive.
    
    - **Database**: lansweeperdb
    
    - **Backup type**: Full
    
    - **Backup component**: Database
    
    ![backing-up-your-installation-2.jpg](https://community.lansweeper.com/t5/image/serverpage/image-id/946iFC921D93418063C8/image-size/large/strip-exif-data/true?v=v2&px=999 "backing-up-your-installation-2.jpg")
    
6.  In the **Media Options** tab of the backup wizard, **tick Verify Backup When Finished.** This ensures the integrity of the backup is checked once created.
    
    ![backing-up-your-installation-3.jpg](https://community.lansweeper.com/t5/image/serverpage/image-id/947i214FD838013632E5/image-size/large/strip-exif-data/true?v=v2&px=999 "backing-up-your-installation-3.jpg")
    
7.  In the **Backup Options** tab of the backup wizard, **make sure the name of the backup set is something other than lansweeperdb**, to avoid overwriting your existing database. Hit OK to create the database backup.
    
    ![backing-up-your-installation-4.jpg](https://community.lansweeper.com/t5/image/serverpage/image-id/948i7C63666988D0D439/image-size/large/strip-exif-data/true?v=v2&px=999 "backing-up-your-installation-4.jpg")
    
8.  **If you added any documents, images, widgets, or other files to Lansweeper, back these up.** Information on which folders store which files can be found in [this knowledge base article](https://community.lansweeper.com/t5/lansweeper-maintenance/where-lansweeper-data-reports-and-settings-are-stored/ta-p/64398#heading2 "Where lansweeper data reports and settings are stored").
    
    ![lightbulb.png](https://community.lansweeper.com/t5/image/serverpage/image-id/770i739C3FE407B8959A/image-size/large/strip-exif-data/true?v=v2&px=999 "lightbulb.png") Do not back up the entire Website folder. Only back up the specific subfolders, you need. Backing up and restoring the entire Website folder can lead to issues.
    
9.  **If it exists, create a backup copy of the following file** as well:
    
    Program Files (x86)\Lansweeper\Key\Encryption.txt
    
10.  **Restart the Lansweeper and web server services** in Windows Services.

		--
		# References
		