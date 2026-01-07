USE SHAREPOINT
go
EXISTS (SELECT
             *
           FROM
             dbo.sysobjects
           WHERE
            id = Object_id(N'[dbo].[GatherVirtualFileStats]')
            AND Objectproperty(id, N'IsProcedure') = 1)
  DROP PROCEDURE [dbo].[GatherVirtualFileStats]
 
GO
 
--------------------------------------------------------------------------------------
--  GatherVirtualFileStats
--  by: Wesley D. Brown
--  date: 02/08/2011
--  mod:  04/14/2011
--  mod:  04/17/2013
 
--  description:
--  This stored procedure is used to sample sys.dm_io_virtual_file_stats to track
--  performance at a database file level. This is useful for finding
--  hotspots on SAN's or under performing IO systems.
 
--  parameters:
--    @Duration  = '01:00:00' How long to run before exiting
--   @IntervalInSeconds = 120 Number of seconds between samples
--@DB            = -1 DB_ID to monitor, -1 for all
--@DBFile        = -1 File_ID of file to monitor, -1 for all
--  usage:
--      DECLARE @RC         INT,
--          @StartTime  DATETIME,
--          @databaseID INT
 
--  SELECT @StartTime = Getdate(),
--         @databaseID = Db_id()
 
--  EXEC @RC = Gathervirtualfilestats
--    '00:45:30',
--    30,
--    10,
--    -1
 
--  SELECT *
--  FROM   dbo.VirtualFileStats
--  WHERE  DBID = 10
--  ORDER  BY RecordID
 
--  platforms:
--  SQL Server 2005
--  SQL Server 2008
--  SQL Server 2008 R2
--  SQL Server 2012
--  tested:
--  SQL Server 2005 SP2
--  SQL Server 2012
---------------------------------------------------------------------------------------
--  *** change log      ***
--  Added history table and perge on start up if there is data in the main table
--  *** end change log  ***
-------------------------------------------------------------------------------------
CREATE PROC dbo.Gathervirtualfilestats
  @Duration          DATETIME = '01:00:00',
  @IntervalInSeconds INT = 120,
  @DB                INT = -1,
  @DBFile            INT = -1
AS
  SET nocount ON
 
  DECLARE
    @StopTime                 DATETIME,
    @LastRecordedDateTime     DATETIME,
    @CurrentDateTime          DATETIME,
    @ErrorNumber              INT,
    @NumberOfRows             INT,
    @ErrorMessageText         NVARCHAR(4000),
    @CurrentServerName        VARCHAR(255),
    @DifferenceInMilliSeconds BIGINT,
    @SQLVersion               VARCHAR(50)
 
    select @SQLVersion =
        substring(version_number,1,charindex(' ',version_number))
        from
        (
        select
            substring(version,charindex('-',version)+2, charindex('(',version)-patindex('%.[0-9]',version)) as version_number from
            (
                select @@version as version
            ) as t
    ) as t
 
    if (charindex('11.',@SQLVersion,0) > 0)
    BEGIN
        IF (@DB = -1)
        BEGIN
            set @DB = NULL
        END
        IF (@DBFile = -1)
        BEGIN
            set @DBFile = NULL
        END
    END
 
  IF EXISTS (SELECT
               1
             FROM
               dbo.VirtualFileStats)
    BEGIN
        IF EXISTS (SELECT
                     *
                   FROM
                     dbo.sysobjects
                   WHERE
                    id = Object_id(N'[dbo].[VirtualFileStats]')
                    AND Objectproperty(id, N'IsTable') = 1)
          BEGIN
              INSERT INTO dbo.VirtualFileStatsHistory
              SELECT
                *
              FROM
                VirtualFileStats;
 
              TRUNCATE TABLE dbo.VirtualFileStats;
          END
    END
 
  SELECT
    @CurrentServerName = Cast(Serverproperty('servername') AS VARCHAR(255))
 
  SET @DifferenceInMilliSeconds = Datediff(ms, CONVERT(DATETIME, '00:00:00', 8), @Duration)
 
  SELECT
    @StopTime = Dateadd(ms, @DifferenceInMilliSeconds, Getdate())
 
  WHILE Getdate() <= @StopTime
    BEGIN
        SELECT
          @LastRecordedDateTime = @CurrentDateTime
 
        SELECT
          @CurrentDateTime = Getdate()
 
        INSERT INTO dbo.VirtualFileStats
                    (ServerName,
                     DBID,
                     FileID,
                     Reads,
                     ReadsFromStart,
                     Writes,
                     WritesFromStart,
                     BytesRead,
                     BytesReadFromStart,
                     BytesWritten,
                     BytesWrittenFromStart,
                     IostallInMilliseconds,
                     IostallInMillisecondsFromStart,
                     IostallReadsInMilliseconds,
                     IostallReadsInMillisecondsFromStart,
                     IostallWritesInMilliseconds,
                     IostallWritesInMillisecondsFromStart,
                     RecordedDateTime,
                     IntervalinMilliseconds,
                     FirstMeasureFromStart)
        SELECT
          @CurrentServerName,
          vfs.database_id,
          vfs.[file_id],
          vfs.num_of_reads - dbaf.ReadsFromStart                            AS Reads,
          vfs.num_of_reads                                                  AS ReadsFromStart,
          vfs.num_of_writes - dbaf.WritesFromStart                          AS Writes,
          vfs.num_of_writes                                                 AS WritesFromStart,
          vfs.num_of_bytes_read - dbaf.BytesReadFromStart                   AS BytesRead,
          vfs.num_of_bytes_read                                             AS BytesReadFromStart,
          vfs.num_of_bytes_written - dbaf.BytesWrittenFromStart             AS BytesWritten,
          vfs.num_of_bytes_written                                          AS BytesWrittenFromStart,
          vfs.io_stall - dbaf.IostallInMillisecondsFromStart                AS IostallInMilliseconds,
          vfs.io_stall                                                      AS IostallInMillisecondsFromStart,
          vfs.io_stall_read_ms - dbaf.IostallReadsInMillisecondsFromStart   AS IostallReadsInMilliseconds,
          vfs.io_stall_read_ms                                              AS IostallReadsInMillisecondsFromStart,
          vfs.io_stall_write_ms - dbaf.IostallWritesInMillisecondsFromStart AS IostallWritesInMilliseconds,
          vfs.io_stall_write_ms                                             AS IostallWritesInMillisecondsFromStart,
          @CurrentDateTime,
          CASE
            WHEN @LastRecordedDateTime IS NULL THEN NULL
            ELSE Datediff(ms, dbaf.RecordedDateTime, @CurrentDateTime)
          END                                                               AS IntervalInMilliseconds,
          CASE
            WHEN @LastRecordedDateTime IS NULL THEN 1
            ELSE 0
          END                                                               AS FirstMeasureFromStart
        FROM
          sys.Dm_io_virtual_file_stats(@DB, @DBFile) vfs
        LEFT OUTER JOIN VirtualFileStats dbaf
          ON vfs.database_id = dbaf.dbid
             AND vfs.[file_id] = dbaf.fileid
        WHERE
          ( @LastRecordedDateTime IS NULL
             OR dbaf.RecordedDateTime = @LastRecordedDateTime )
 
        SELECT
          @ErrorNumber = @@ERROR,
          @NumberOfRows = @@ROWCOUNT
 
        IF @ErrorNumber != 0
          BEGIN
              SET @ErrorMessageText = 'Error ' + CONVERT(VARCHAR(10), @ErrorNumber) + ' failed to insert file stats data!'
 
              RAISERROR (@ErrorMessageText,
                         16,
                         1) WITH LOG
 
              RETURN @ErrorNumber
          END
 
        WAITFOR DELAY @IntervalInSeconds
    END
GO