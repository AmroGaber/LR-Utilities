/****** Script for SelectTopNRows command from SSMS  ******/
SELECT TOP 1 [StatsDeploymentCountsMinuteID]
      ,[StatDate]
      ,[CountLogs]
      ,[CountProcessedLogs]
      ,[CountIdentitfiedLogs]
      ,[CountArchivedLogs]
      ,[CountOnlineLogs]
      ,[CountEvents]
      ,[CountEventsForwarded]
      ,[EventsRBPSum]
      ,[EventsForwardedRBPSum]
      ,[CountLogMart]
      ,[CountEventsAIEngine]
      ,[CountAlarms]
      ,[CountEventsRBP10]
      ,[CountEventsRBP20]
      ,[CountEventsRBP30]
      ,[CountEventsRBP40]
      ,[CountEventsRBP50]
      ,[CountEventsRBP60]
      ,[CountEventsRBP70]
      ,[CountEventsRBP80]
      ,[CountEventsRBP90]
      ,[CountEventsRBP100]
      ,[EventsAIEngineRBPSum]
      ,[CountAnalyzedLogs]
  FROM [LogRhythm_LogMart].[dbo].[StatsDeploymentCountsMinute]
  WHERE StatDate > DATEADD(minute, -2, GETUTCDATE()) 
  ORDER BY StatsDeploymentCountsMinuteID DESC

  
