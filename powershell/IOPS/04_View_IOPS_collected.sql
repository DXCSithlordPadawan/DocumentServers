SELECT TOP 10 Db_name(dbid)                                          AS 'databasename',
              File_name(fileid)                                      AS 'filename',
              Reads / ( IntervalInMilliSeconds / 1000 )              AS 'readspersecond',
              Writes / ( IntervalInMilliSeconds / 1000 )             AS 'writespersecond',
              ( Reads + Writes ) / ( IntervalInMilliSeconds / 1000 ) AS 'iopersecond',
              CASE
                WHEN ( Reads / ( IntervalInMilliSeconds / 1000 ) ) > 0
                     AND IostallReadsInMilliseconds > 0 THEN IostallReadsInMilliseconds / Reads
                ELSE 0
              END                                                    AS 'iolatencyreads',
              CASE
                WHEN ( Reads / ( IntervalInMilliSeconds / 1000 ) ) > 0
                     AND IostallWritesInMilliseconds > 0 THEN IostallWritesInMilliseconds / Writes
                ELSE 0
              END                                                    AS 'iolatencywrites',
              CASE
                WHEN ( ( Reads + Writes ) / ( IntervalInMilliSeconds / 1000 ) > 0
                       AND IostallInMilliseconds > 0 ) THEN IostallInMilliseconds / ( Reads + Writes )
                ELSE 0
              END                                                    AS 'iolatency',
              RecordedDateTime
FROM   dbo.VirtualFileStats
WHERE  DBID = 5
       AND FirstMeasureFromStart = 0
ORDER  BY RecordID
