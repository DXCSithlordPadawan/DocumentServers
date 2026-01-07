USE SHAREPOINT
go
CREATE TABLE dbo.VirtualFileStats
  (
     RecordID                             INT IDENTITY(1,1) NOT NULL,
     ServerName                           VARCHAR(255) NOT NULL,
     DBID                                 INT NOT NULL,
     FileID                               INT NOT NULL,
     Reads                                BIGINT NULL,
     ReadsFromStart                       BIGINT NULL,
     Writes                               BIGINT NULL,
     WritesFromStart                      BIGINT NULL,
     BytesRead                            BIGINT NULL,
     BytesReadFromStart                   BIGINT NULL,
     BytesWritten                         BIGINT NULL,
     BytesWrittenFromStart                BIGINT NULL,
     IostallInMilliseconds                BIGINT NULL,
     IostallInMillisecondsFromStart       BIGINT NULL,
     IostallReadsInMilliseconds           BIGINT NULL,
     IostallReadsInMillisecondsFromStart  BIGINT NULL,
     IostallWritesInMilliseconds          BIGINT NULL,
     IostallWritesInMillisecondsFromStart BIGINT NULL,
     RecordedDateTime                     DATETIME NULL,
     IntervalInMilliseconds               BIGINT NULL,
     FirstMeasureFromStart                BIT NULL
  )
GO
CREATE TABLE dbo.VirtualFileStatsHistory
  (
     RecordID                             INT NOT NULL,
     ServerName                           VARCHAR(255) NOT NULL,
     DBID                                 INT NOT NULL,
     FileID                               INT NOT NULL,
     Reads                                BIGINT NULL,
     ReadsFromStart                       BIGINT NULL,
     Writes                               BIGINT NULL,
     WritesFromStart                      BIGINT NULL,
     BytesRead                            BIGINT NULL,
     BytesReadFromStart                   BIGINT NULL,
     BytesWritten                         BIGINT NULL,
     BytesWrittenFromStart                BIGINT NULL,
     IostallInMilliseconds                BIGINT NULL,
     IostallInMillisecondsFromStart       BIGINT NULL,
     IostallReadsInMilliseconds           BIGINT NULL,
     IostallReadsInMillisecondsFromStart  BIGINT NULL,
     IostallWritesInMilliseconds          BIGINT NULL,
     IostallWritesInMillisecondsFromStart BIGINT NULL,
     RecordedDateTime                     DATETIME NULL,
     IntervalInMilliseconds               BIGINT NULL,
     FirstMeasureFromStart                BIT NULL
  )
GO