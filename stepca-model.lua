-- Alpine Configuration Framework (ACF) Model for step-ca
-- Model handles business logic and system interaction for PKI

local mymodule = {}

local posix = require("posix")
local format = require("acf.format")
local fs = require("acf.fs")
local processinfo = require("acf.processinfo")
local modelfunctions = require("modelfunctions")

-- ============================================================================
-- Basic Helper Functions (must be first)
-- ============================================================================

-- Helper function to execute command and return output
local function exec_command(cmd)
    local handle = io.popen(cmd)
    if not handle then return "" end
    local result = handle:read("*a")
    handle:close()
    return result or ""
end

-- Helper to check if jq is installed
local function has_jq()
    local res = exec_command("which jq 2>/dev/null")
    return res ~= ""
end

-- Helper to check if step-badger is installed
local function has_step_badger()
    local res = exec_command("which step-badger 2>/dev/null")
    return res ~= ""
end

-- Helper function to check if file exists
local function file_exists(path)
    local f = io.open(path, "r")
    if f then
        f:close()
        return true
    end
    return false
end

-- ============================================================================
-- Configuration paths (Alpine Linux standard paths from step-certificates pkg)
-- ============================================================================
local packagename = "step-certificates"
local servicename = "step-ca"

-- Helper script directory (injected by Makefile)
local LIBEXEC = "@@LIBEXECDIR@@"

-- Default paths for Alpine Linux
local step_ca_base = "/etc/step-ca"
local default_port = "9000"

-- Check for override config file (for Home Assistant addon, etc.)
local config_override = "/usr/share/acf/app/stepca/stepca.conf"
local override_file = io.open(config_override, "r")
if override_file then
    for line in override_file:lines() do
        local key, value = line:match("^([^=]+)=(.+)$")
        if key == "STEPPATH" then
            step_ca_base = value:gsub('"', ''):gsub("'", '')
        elseif key == "STEPPORT" then
            default_port = value:gsub('"', ''):gsub("'", '')
        end
    end
    override_file:close()
end

local step_config = step_ca_base .. "/config/ca.json"
local step_certs_path = step_ca_base .. "/certs"
local step_secrets_path = step_ca_base .. "/secrets"
local step_db_path = step_ca_base .. "/db"
local step_password_file = step_ca_base .. "/password.txt"
local step_log = "/var/log/step-ca/step-ca.log"
local crl_path = "/var/lib/step-ca/crl.pem"
local acf_config_file = step_ca_base .. "/acf-config.conf"

-- Helper function to create CFE (Configuration Framework Entity)
local function create_cfe(name, value, label, descr, cfetype, option)
    return {
        name = name or "",
        value = value or "",
        label = label or "",
        descr = descr or "",
        type = cfetype or "text",
        option = option or {}
    }
end

-- Helper function to validate hostname/FQDN format
-- Returns: nil on success, or error message string on failure
local function validate_hostname(hostname, field_name)
    field_name = field_name or "Hostname"

    -- Check for invalid characters (only alphanumeric, dash, dot, and underscore allowed)
    if hostname:match("[^a-zA-Z0-9%.%-%_]") then
        return field_name .. " has invalid chars. Only letters, numbers, dots, dashes, and underscores allowed."
    end

    -- Check for double dots
    if hostname:match("%.%.") then
        return field_name .. " cannot contain consecutive dots (..)"
    end

    -- Check for leading/trailing dots or dashes
    if hostname:match("^[%.%-]") or hostname:match("[%.%-]$") then
        return field_name .. " cannot start or end with a dot or dash"
    end

    -- Check length (DNS labels max 63 chars, FQDN max 253 chars)
    if #hostname > 253 then
        return field_name .. " is too long (max 253 characters)"
    end

    -- Check individual labels don't exceed 63 characters
    for label in hostname:gmatch("[^%.]+") do
        if #label > 63 then
            return field_name .. " label '" .. label .. "' is too long (max 63 characters per label)"
        end
    end

    return nil  -- No errors
    end

    -- Helper function to discover CA address/port from ca.json
local function get_ca_address()
    local port = default_port
    local host = "localhost"

    if posix.stat(step_config) ~= nil then
        -- Discover hostname from dnsNames
        if has_jq() then
            local dns = exec_command("jq -r '.dnsNames[0] // \"\"' " .. step_config):gsub("%s+", "")
            if dns ~= "" and dns ~= "null" then host = dns end
        else
            local content = fs.read_file(step_config)
            local dns = content:match('"dnsNames"%s*:%s*%[%s*"([^"]+)"')
            if dns then host = dns end
        end

        local addr
        if has_jq() then
            addr = exec_command("jq -r '.address // \"\"' " .. step_config):gsub("%s+", "")
        else
            local content = fs.read_file(step_config)
            addr = content:match('"address"%s*:%s*"([^"]+)"')
        end

        if addr and addr ~= "" and addr ~= "null" then
            if addr:match("^:") then
                return "https://" .. host .. addr
            else
                -- If it already has a hostname, use it
                if not addr:match("://") then addr = "https://" .. addr end
                return addr
            end
        end
    end
    return "https://" .. host .. ":" .. port
end

-- Helper function to get step-ca user from config
local function get_stepca_user()
    local default_user = "step-ca"

    local f = io.open(acf_config_file, "r")
    if f then
        local conf_content = f:read("*a")
        f:close()
        for line in conf_content:gmatch("[^\n]+") do
            local key, value = line:match("^([^=]+)=(.+)$")
            if key == "STEPCA_USER" then
                return value
            end
        end
    end

    return default_user
end

-- Helper function to execute command as step-ca user via su
-- This ensures files created by step ca commands are owned by step-ca user
local function exec_as_stepca(cmd)
    local stepca_user = get_stepca_user()
    -- Construct a command that sets the environment and runs the cmd
    -- 1. Set TERM=dumb to prevent Go terminal allocation errors
    -- 2. Set PATH and STEPPATH
    -- 3. Load CA password into STEP_CA_PASSWORD
    -- 4. Use single quotes for the inner command to prevent premature expansion
    local wrapped_cmd = string.format(
        "su %s -s /bin/sh -c \"export TERM=dumb; export PATH='/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin'; " ..
        "export STEPPATH='%s'; " ..
        "export STEP_CA_PASSWORD=\\$(cat '%s' 2>/dev/null); " ..
        "%s\"",
        stepca_user, step_ca_base, step_password_file, cmd:gsub('"', '\\"'):gsub("%$", "\\$")
    )
    return exec_command(wrapped_cmd)
end

-- Assemble a step CLI argument string guaranteeing ALL flags precede ALL positionals.
-- This version of step uses POSIX-strict flag parsing: once a non-flag token is seen,
-- every subsequent token is treated as a positional argument.
-- flags: array of pre-formatted flag strings (e.g. "--provisioner='admin'")
-- positionals: array of bare values (will be single-quoted automatically)
local function build_step_args(flags, positionals)
    local parts = {}
    for _, f in ipairs(flags or {}) do
        if f and f ~= "" then table.insert(parts, f) end
    end
    for _, p in ipairs(positionals or {}) do
        table.insert(parts, string.format("'%s'", p))
    end
    return table.concat(parts, " ")
end

-- Wrapper for executing step commands.
-- track: "ca" (for 'step ca ...') or "base" (for 'step certificate ...')
-- subaction: the command (e.g., 'certificate', 'provisioner', 'create', 'sign')
-- flags: table of pre-formatted flag strings
-- positionals: table of bare positional values (single-quoted by build_step_args)
-- options: { use_pass = bool, pass_flag = string, force = bool, use_api = bool }
local function stepca_exec(track, subaction, flags, positionals, options)
    options = options or {}
    local cmd_base = (track == "ca") and "step ca" or "step certificate"
    local cmd = cmd_base
    if subaction and subaction ~= "" then
        cmd = cmd .. " " .. subaction
    end

    -- Infrastructure flags always prepended (before caller flags, before positionals)
    local infra = {}
    if track == "ca" then
        table.insert(infra, string.format("--ca-config='%s'", step_config))
    end
    -- NOTE: do NOT use --admin-password-file here; only valid for step ca admin/provisioner
    if options.use_pass then
        local pass_flag = options.pass_flag or "--password-file"
        table.insert(infra, string.format("%s='%s'", pass_flag, step_password_file))
    end
    if options.use_api then
        local ca_url = get_ca_address()
        local root_ca = step_certs_path .. "/root_ca.crt"
        table.insert(infra, string.format("--ca-url='%s'", ca_url))
        table.insert(infra, string.format("--root='%s'", root_ca))
    end
    if options.force then
        table.insert(infra, "--force")
    end

    -- Merge infra + caller flags, then positionals last via build_step_args
    local all_flags = {}
    for _, f in ipairs(infra)          do table.insert(all_flags, f) end
    for _, f in ipairs(flags or {})    do table.insert(all_flags, f) end

    cmd = cmd .. " " .. build_step_args(all_flags, positionals) .. " 2>&1"
    return exec_as_stepca(cmd)
end

-- ============================================================================
-- JSON-Based Metadata Extraction
-- ============================================================================

local function get_cert_metadata(cert_path)
    if not file_exists(cert_path) then return nil end

    -- We need the serial in hex to match step-badger, but JSON gives decimal.
    -- We'll get both by using two passes or parsing text.
    local text_cmd = string.format("step certificate inspect %s 2>/dev/null", cert_path)
    local text_output = exec_command(text_cmd)

    local meta = {}
    -- Extract decimal serial from "Serial Number: <decimal> (0x<hex>)"
    -- step ca revoke and step ca token both require decimal to match the JWT subject.
    local dec_serial = text_output:match("Serial Number:%s+(%d+)%s+%(")
    if dec_serial and dec_serial ~= "" then
        meta.serial = dec_serial
    end

    -- Now get the rest from JSON for accuracy
    local json_cmd = string.format("step certificate inspect --format json %s 2>/dev/null", cert_path)
    local json_output = exec_command(json_cmd)

    if has_jq() then
        local jq_cmd = "echo '%s' | jq -r '%s'"
        local sub_filter = ".subject.common_name[0] // .subject[0] // .subject_dn"
        meta.subject = exec_command(string.format(jq_cmd, json_output:gsub("'", "'\\''"), sub_filter)):gsub("%s+", "")

        -- Fallback: get decimal serial from JSON .serial_number if text extraction failed
        if not meta.serial then
            local ser_filter = ".serial_number"
            local escaped = json_output:gsub("'", "'\\''")
            meta.serial = exec_command(string.format(jq_cmd, escaped, ser_filter)):gsub("%s+", "")
            if meta.serial == "" then meta.serial = nil end
        end

        local escaped_out = json_output:gsub("'", "'\\''")
        meta.not_after = exec_command(string.format(jq_cmd, escaped_out, ".validity.end")):gsub("%s+", "")
        meta.not_before = exec_command(string.format(jq_cmd, escaped_out, ".validity.start")):gsub("%s+", "")

        -- Detect EKU accurately (extract keys as strings)
        local eku_filter = ".extensions.extended_key_usage | keys[] // empty"
        local ekus = exec_command(string.format(jq_cmd, json_output:gsub("'", "'\\''"), eku_filter))
        meta.has_server_auth = ekus:match("server_auth") or ekus:match("1.3.6.1.5.5.7.3.1")
        meta.has_client_auth = ekus:match("client_auth") or ekus:match("1.3.6.1.5.5.7.3.2")

        -- Detect CA status
        local ca_filter = ".extensions.basic_constraints.is_ca // false"
        meta.is_ca = exec_command(string.format(jq_cmd, json_output:gsub("'", "'\\''"), ca_filter)):match("true")
    else
        -- Fallback to text parsing if JQ is missing
        local inspect_text = text_output -- Use the text output we already got
        meta.subject = inspect_text:match("Subject:.*CN=([^,\n]+)") or inspect_text:match("Subject: ([^\n]+)") or ""
        -- meta.serial is already set from text_output at the top of the function
        meta.not_after = inspect_text:match("Not After : ([^\n]+)") or ""
        meta.has_server_auth = inspect_text:match("Server Authentication")
        meta.has_client_auth = inspect_text:match("Client Authentication")
        meta.is_ca = inspect_text:match("CA: true") or inspect_text:match("CA:TRUE")
    end

    return meta
end

-- Helper to convert user-friendly durations (like 365d) to Step-CA format (8760h)
-- Step-CA natively supports s, m, h. We add support for d (days).
local function normalize_duration(input)
    if not input or input == "" then return nil end
    local val, unit = input:match("^(%d+)([hdms])$")
    if unit == "d" then
        return (tonumber(val) * 24) .. "h"
    end
    return input -- Return as-is for h, m, s
end

-- Helper to validate duration format
local function validate_duration(input, field_name)
    if not input or input == "" then return nil end -- Allow empty (skipped)

    if not input:match("^%d+[hdms]$") then
        local msg = "Invalid format for %s: '%s'. Use a number followed by s, m, h, or d (e.g., 24h, 365d)."
        return string.format(msg, field_name, input)
    end
    return nil
end

-- Helper function to calculate days until certificate expiration
local function get_cert_expiration_days(cert_path)
    if not file_exists(cert_path) then
        return nil
    end

    -- Get expiration date without jq - use grep/sed to extract from text output
    local cmd = "step certificate inspect " .. cert_path .. " 2>/dev/null | grep 'Not After' | head -1"
    local exp_line = exec_command(cmd)

    if not exp_line or exp_line == "" then
        return nil
    end

    -- Extract date from format: "Not After: 2025-12-31 23:59:59 +0000 UTC"
    -- or "Not After: Feb 28 04:42:00 2027 UTC"
    local year, month, day

    -- Try ISO format first (2025-12-31)
    year, month, day = exp_line:match("(%d%d%d%d)%-(%d%d)%-(%d%d)")

    -- If not ISO, try text month format (Feb 28 ... 2027)
    if not year then
        local month_str, day_str, year_str = exp_line:match("(%a+)%s+(%d+)%s+%d+:%d+:%d+%s+(%d%d%d%d)")
        if month_str then
            -- Convert month name to number
            local months = {Jan=1, Feb=2, Mar=3, Apr=4, May=5, Jun=6, Jul=7, Aug=8, Sep=9, Oct=10, Nov=11, Dec=12}
            month = months[month_str]
            day = tonumber(day_str)
            year = tonumber(year_str)
        end
    else
        year = tonumber(year)
        month = tonumber(month)
        day = tonumber(day)
    end

    if not year or not month or not day then
        return nil
    end

    local exp_time = os.time({year=year, month=month, day=day, hour=23, min=59, sec=59})
    local now = os.time()
    local days = math.floor((exp_time - now) / 86400)

    return days
end

-- Helper function to parse Step-CA date format to os.time
local function parse_date_to_epoch(date_str)
    if not date_str or date_str == "" or date_str == "null" then return nil end

    -- ISO Format (step json): 2026-03-04T23:04:34Z
    local year, month, day, hour, min, sec = date_str:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)Z")

    if not year then
        -- ISO Format with fractional seconds: 2026-03-04T23:04:34.000Z
        year, month, day, hour, min, sec = date_str:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)%.%d+Z")
    end

    if not year then
        -- ISO Format with timezone: 2026-03-04T23:04:34+00:00
        year, month, day, hour, min, sec = date_str:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)[%+%-]%d+:%d+")
    end

    if not year then
        -- Try ISO format without T separator (some step outputs)
        year, month, day, hour, min, sec = date_str:match("(%d%d%d%d)%-(%d%d)%-(%d%d)%s+(%d+):(%d+):(%d+)")
    end

    if not year then
        -- Alternate format: Mar 5 00:00:00 2025 UTC
        local pat = "(%a+)%s+(%d+)%s+(%d+):(%d+):(%d+)%s+(%d+)"
        local month_name, day_str, hour_str, min_str, sec_str, year_str = date_str:match(pat)
        if month_name then
            local months = {Jan=1, Feb=2, Mar=3, Apr=4, May=5, Jun=6, Jul=7, Aug=8, Sep=9, Oct=10, Nov=11, Dec=12}
            month = months[month_name]
            day = tonumber(day_str)
            hour = tonumber(hour_str)
            min = tonumber(min_str)
            sec = tonumber(sec_str)
            year = tonumber(year_str)
        end
    else
        year = tonumber(year)
        month = tonumber(month)
        day = tonumber(day)
        hour = tonumber(hour)
        min = tonumber(min)
        sec = tonumber(sec)
    end

    if not year or not month or not day then
        return nil
    end

    return os.time({year=year, month=month, day=day, hour=hour or 0, min=min or 0, sec=sec or 0})
end

-- Helper function to detect certificate type from extensions
local function detect_cert_type(cert_path, cert_name)
    -- System certs by filename
    if cert_name == "root_ca" then return "Root CA", true end
    if cert_name == "intermediate_ca" then return "Intermediate CA", true end

    local meta = get_cert_metadata(cert_path)
    if not meta then return "Unknown", false end

    if meta.is_ca then return "CA", false end

    if meta.has_server_auth and meta.has_client_auth then
        return "Client-Server", false
    elseif meta.has_server_auth then
        return "Server", false
    elseif meta.has_client_auth then
        return "Client", false
    end

    return "User Certificate", false
end

-- Helper function to classify certificate as infrastructure or ephemeral
local function is_infrastructure_cert(cert_type)
    local infra = {
        ["Root CA"] = true, ["Intermediate CA"] = true, ["CA"] = true,
        ["Server"] = true, ["Client-Server"] = true
    }

    -- Client (pure client auth) and User Certs are Ephemeral
    if cert_type == "Client" or cert_type == "User Certificate" then
        return false
    end

    return infra[cert_type] == true
end

-- Determine whether an expired certificate should be shown given the user's
-- chosen expired_window sub-filter and the cert's own properties.
-- finish_epoch : unix timestamp of cert NotAfter (nil = unknown, treat as not expired)
-- total_lifetime_days : cert lifetime in days (nil = unknown)
-- is_infra : bool — infrastructure cert (Root CA, Intermediate CA, Server, etc.)
-- expired_window : "smart" | "24h" | "1w" | "all"
local function show_expired(finish_epoch, total_lifetime_days, is_infra, expired_window)
    local now = os.time()
    -- Not expired at all — always show
    if not finish_epoch or finish_epoch > now then return true end

    local expired_secs = now - finish_epoch  -- seconds since expiry

    if expired_window == "all" then
        return true
    elseif expired_window == "1w" then
        return expired_secs <= (7 * 86400)
    elseif expired_window == "24h" then
        return expired_secs <= 86400
    else -- "smart" (default)
        -- Infrastructure: always show regardless of age
        if is_infra then return true end
        -- Longer-lived ephemeral (>48h total lifetime): hide after 1 week
        if total_lifetime_days and total_lifetime_days > 2 then
            return expired_secs <= (7 * 86400)
        end
        -- Short-lived ephemeral (≤48h lifetime): hide after 24h
        return expired_secs <= 86400
    end
end

-- Helper function to read thresholds from config file
local function get_thresholds_from_config()
    local thresholds = {
        critical_days = 7,
        warning_days = 30,
        notice_days = 90,
        critical_percent = 10,
        warning_percent = 30,
        notice_percent = 50
    }

    if file_exists(acf_config_file) then
        local conf_content = fs.read_file(acf_config_file)
        for line in conf_content:gmatch("[^\n]+") do
            local key, value = line:match("^([^=]+)=(.+)$")
            if key and value then
                if key == "CRITICAL_DAYS" then
                    thresholds.critical_days = tonumber(value) or 7
                elseif key == "WARNING_DAYS" then
                    thresholds.warning_days = tonumber(value) or 30
                elseif key == "NOTICE_DAYS" then
                    thresholds.notice_days = tonumber(value) or 90
                elseif key == "CRITICAL_PERCENT" then
                    thresholds.critical_percent = tonumber(value) or 10
                elseif key == "WARNING_PERCENT" then
                    thresholds.warning_percent = tonumber(value) or 30
                elseif key == "NOTICE_PERCENT" then
                    thresholds.notice_percent = tonumber(value) or 50
                end
            end
        end
    end

    return thresholds
end

-- Helper function to get expiration status color/label
-- Now cert_type aware: uses percentage thresholds for ephemeral, days for infrastructure
local function get_expiration_status(days, cert_type, total_lifetime_days)
    if not days then
        return "Unknown", "gray"
    elseif days < 0 then
        return "Expired", "red"
    end

    -- Get thresholds from config file
    local thresholds = get_thresholds_from_config()

    -- Determine if this is infrastructure or ephemeral
    local is_infra = is_infrastructure_cert(cert_type or "User Certificate")

    if is_infra then
        -- Infrastructure: Use fixed day thresholds (configurable)
        if days <= thresholds.critical_days then
            return "Critical", "red"
        elseif days <= thresholds.warning_days then
            return "Warning", "yellow"
        elseif days <= thresholds.notice_days then
            return "Soon", "blue"
        else
            return "Valid", "green"
        end
    else
        -- Ephemeral (WiFi, etc): Use percentage thresholds (configurable)
        if not total_lifetime_days or total_lifetime_days == 0 then
            -- Fallback to days if we can't calculate percentage
            if days <= 1 then
                return "Critical", "red"
            elseif days <= 3 then
                return "Warning", "yellow"
            else
                return "Valid", "green"
            end
        end

        local remaining_percent = (days / total_lifetime_days) * 100

        if remaining_percent <= thresholds.critical_percent then
            return "Critical", "red"
        elseif remaining_percent <= thresholds.warning_percent then
            return "Warning", "yellow"
        elseif remaining_percent <= thresholds.notice_percent then
            return "Soon", "blue"
        else
            return "Valid", "green"
        end
    end
end

-- Helper function to query BadgerDB for revoked certificates
-- Returns: table with {success=boolean, data=string, error=string}
-- This centralizes all step-badger query logic to avoid duplication
local function query_revoked_certificates()
    local result = {success = false, data = nil, error = nil}

    -- Verify database exists
    if not file_exists(step_db_path) then
        result.error = "Database not found at " .. step_db_path
        return result
    end

    -- Construct compound command to avoid external script dependency
    local full_cmd = string.format(
        "T=$(mktemp -d /tmp/step-revoked.XXXXXX); cp -r '%s'/* $T/ 2>/dev/null; " ..
        "export PATH='/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin'; " ..
        "step-badger x509Certs $T -r --emit openssl --serial hex 2>/dev/null | grep '^R'; " ..
        "rm -rf $T",
        step_db_path
    )

    local query_output = exec_command(full_cmd)

    -- Validate output
    if query_output then
        query_output = query_output:gsub("^%s+", ""):gsub("%s+$", "")

        -- Check for errors (mktemp/cp errors don't usually start with ERROR)
        if query_output:match("^ERROR") or query_output:match("^panic") or query_output:match("^Error") then
            result.error = "step-badger query failed: " .. query_output
            return result
        end

        -- Success - return data (empty string means no revocations)
        result.success = true
        result.data = query_output
    else
        result.error = "step-badger query returned no output"
    end

    return result
end

-- Helper function to check if a certificate is revoked
-- Returns: true if revoked, false if not revoked, nil if unable to determine
-- Uses step-badger to query the BadgerDB database directly
local function is_certificate_revoked(serial)
    if not serial or serial == "" then
        return nil
    end

    -- Normalize serial for matching
    local norm_serial = serial:upper():gsub("^0X", ""):gsub("^0+", "")
    if norm_serial == "" then norm_serial = "0" end

    -- Use our optimized query helper
    local query_result = query_revoked_certificates()
    if not query_result.success or not query_result.data then
        return false
    end

    -- Search for the serial in the output
    -- Serial is the 4th field in OpenSSL R format
    for line in query_result.data:gmatch("[^\n]+") do
        local parts = {}
        for part in line:gmatch("%S+") do table.insert(parts, part) end
        if #parts >= 4 then
            local db_serial = parts[4]:upper():gsub("^0X", ""):gsub("^0+", "")
            if db_serial == "" then db_serial = "0" end
            if db_serial == norm_serial then
                return true
            end
        end
    end

    return false
end

-- Get system status (PKI parts)
function mymodule.get_status()
    local status = {}

    -- Check if CA is initialized
    status.ca_initialized = create_cfe(
        "ca_initialized",
        tostring(file_exists(step_config)),
        "CA Initialized",
        "Certificate Authority initialization status",
        "boolean"
    )

    -- Get step-ca service status
    local step_status = exec_command("rc-service step-ca status 2>&1")
    status.step_ca_status = create_cfe(
        "step_ca_status",
        step_status:match("started") and "running" or "stopped",
        "step-ca Service",
        "Certificate Authority service status",
        "text"
    )

    -- Count certificates
    local cert_count = exec_command("ls " .. step_certs_path .. "/*.crt 2>/dev/null | wc -l")
    status.certificate_count = create_cfe(
        "certificate_count",
        cert_count:gsub("%s+", ""),
        "Total Certificates",
        "Number of certificates in the system",
        "text"
    )

    -- Get CA certificate info (formatted, not raw JSON)
    if file_exists(step_certs_path .. "/root_ca.crt") then
        local ca_info = exec_command("step certificate inspect " .. step_certs_path .. "/root_ca.crt 2>/dev/null")
        status.ca_info = create_cfe(
            "ca_info",
            ca_info,
            "Root CA Information",
            "Root Certificate Authority details",
            "longtext"
        )
    end

    -- CRL status - skip since we don't use CRL files
    -- Revocation status is tracked in BadgerDB and queried via step-badger

    return status
end

-- Restart the step-ca service
function mymodule.get_startstop(self, clientdata)
    return modelfunctions.get_startstop(servicename)
end

function mymodule.startstop_service(self, startstop, action)
    return modelfunctions.startstop_service(startstop, action)
end

function mymodule.restart_service()
    local output, errtxt = processinfo.daemoncontrol(servicename, "restart")
    return output or errtxt or ""
end

-- Helper function to query BadgerDB for all certificates in bulk
-- Returns: table of serial_hex -> metadata, and execution time in seconds
local function load_bulk_certificate_data()
    local bulk_data = {}

    -- Construct compound command to avoid external script dependency
    -- 1. Create temp dir
    -- 2. Copy DB files
    -- 3. Run step-badger with -r (all certificates)
    -- 4. Cleanup
    local cmd = string.format(
        "T=$(mktemp -d /tmp/step-bulk.XXXXXX); cp -r '%s'/* $T/ 2>/dev/null; " ..
        "export PATH='/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin'; " ..
        "step-badger x509Certs $T -r --emit openssl --serial hex 2>/dev/null; " ..
        "rm -rf $T",
        step_db_path
    )

    -- Run as root for maximum reliability (reading DB)
    local start_time = os.clock()
    local output = exec_command(cmd)
    local end_time = os.clock()

    -- If output is empty or contains an error, step-badger failed or is missing
    if not output or output == "" or output:lower():match("error") then
        return bulk_data, nil
    end

    local exec_time = end_time - start_time
    local found_data = false
    -- Parse OpenSSL-formatted output:
    -- V    expiry    serial_hex    subject
    -- R    expiry    revoke_date    serial_hex    reason    subject
    for line in output:gmatch("[^\n]+") do
        local parts = {}
        for part in line:gmatch("%S+") do
            table.insert(parts, part)
        end

        if #parts >= 4 then
            local status_flag = parts[1]
            local meta = {}
            local serial = ""

            if status_flag == "V" then
                -- Valid: V, expiry, serial, subject...
                serial = parts[3]:upper():gsub("^0X", ""):gsub("^0+", "")
                if serial == "" then serial = "0" end
                meta.status = "Valid"
                meta.not_after = parts[2]
                -- Subject starts at 4th non-space block
                meta.subject = line:match("%S+%s+%S+%s+%S+%s+(.*)") or "Unknown"
            elseif status_flag == "R" then
                -- Revoked: R, expiry, revoke_date, serial, reason, subject...
                serial = parts[4]:upper():gsub("^0X", ""):gsub("^0+", "")
                if serial == "" then serial = "0" end
                meta.status = "Revoked"
                meta.not_after = parts[2]
                -- Subject starts at 6th non-space block
                meta.subject = line:match("%S+%s+%S+%s+%S+%s+%S+%s+%S+%s+(.*)") or "Unknown"
            end

            if serial ~= "" then
                -- Match step-cli behavior: serial might be padded
                -- We'll store it normalized
                bulk_data[serial] = meta
                found_data = true
            end
        end
    end

    return bulk_data, (found_data and exec_time or nil)
end

-- Forward declaration: defined later after the helper functions it uses.
local list_certs_from_badger

-- List all certificates.
-- Uses step-badger (fast, rich metadata) when available; falls back to file parsing.
function mymodule.list_certificates(clientdata)
    if has_step_badger() then
        return list_certs_from_badger(clientdata)
    end

    clientdata = clientdata or {}
    local filter         = clientdata.filter         or "all"
    local expired_window = clientdata.expired_window or "smart"
    local certs = {}

    -- Load bulk data from DB first (fast)
    local db_certs, db_exec_time = load_bulk_certificate_data()

    -- Execute ls on the certs directory to get filenames (source of truth)
    local cert_files_output = exec_command("ls -1 " .. step_certs_path .. " 2>/dev/null")

    for filename in cert_files_output:gmatch("[^\n]+") do
        -- Only process .crt files
        local cert_name = filename:match("(.+)%.crt$")

        if cert_name then
            local cert_file = step_certs_path .. "/" .. filename

            -- 1. Try to find metadata in bulk DB data
            local meta = get_cert_metadata(cert_file)
            if meta then
                local serial = meta.serial
                local db_meta = db_certs[serial]

                -- Detect certificate type
                local cert_type, is_system_cert = detect_cert_type(cert_file, cert_name)

                -- Use DB data if available, otherwise use live inspection
                local status = db_meta and db_meta.status or "Valid"
                local subject = meta.subject
                local not_after = meta.not_after
                local not_before = meta.not_before

                -- Calculate lifetime/expiration
                local days_remaining = nil
                local total_lifetime_days = nil

                local exp_epoch = parse_date_to_epoch(not_after)
                local start_epoch = parse_date_to_epoch(not_before)

                if exp_epoch then
                    days_remaining = math.floor((exp_epoch - os.time()) / 86400)
                    if start_epoch then
                        total_lifetime_days = math.floor((exp_epoch - start_epoch) / 86400)
                    end
                end

                local calc_status, color = get_expiration_status(days_remaining, cert_type, total_lifetime_days)

                -- Overwrite status if DB says it's revoked
                if status == "Revoked" then
                    calc_status = "Revoked"
                    color = "red"
                end

                table.insert(certs, {
                    name = create_cfe("name", cert_name, "Certificate Name", "Certificate filename", "text"),
                    subject = create_cfe("subject", subject, "Common Name", "Certificate CN", "text"),
                    serial = create_cfe("serial", serial, "Serial Number", "Certificate serial number", "text"),
                    cert_type = create_cfe("cert_type", cert_type, "Type", "Certificate type", "text"),
                    is_system_cert = create_cfe(
                        "is_system_cert", tostring(is_system_cert), "System Cert", "Managed", "text"
                    ),
                    is_revoked = create_cfe(
                        "is_revoked", tostring(status == "Revoked"), "Revoked", "Is revoked", "boolean"
                    ),
                    path = create_cfe("path", cert_file, "File Path", "Path to file", "text"),
                    days_remaining = create_cfe(
                        "days_remaining", tostring(days_remaining or "N/A"), "Days Left", "Days left", "text"
                    ),
                    expiration_date = create_cfe("expiration_date", not_after, "Expiration", "Expiration date", "text"),
                    status = create_cfe("status", calc_status, "Status", "Expiration/Revocation status", "text"),
                    color = create_cfe("color", color, "Status Color", "Status indicator color", "text"),
                    -- Raw values used by the expired-window sub-filter (not rendered by the view)
                    _finish_epoch    = exp_epoch,
                    _lifetime_days   = total_lifetime_days,
                })
            end
        end
    end

    -- Apply type + expired-window filters
    local visible = {}
    for _, cert in ipairs(certs) do
        local cert_type  = cert.cert_type.value
        local is_infra   = is_infrastructure_cert(cert_type)

        -- Type filter
        local type_ok
        if filter == "infrastructure" then     type_ok = is_infra
        elseif filter == "ephemeral" then      type_ok = not is_infra
        else                                   type_ok = true
        end

        -- Expired-window sub-filter (uses raw epoch/lifetime stored during build)
        local window_ok = show_expired(cert._finish_epoch, cert._lifetime_days, is_infra, expired_window)

        if type_ok and window_ok then
            table.insert(visible, cert)
        end
    end

    return {
        certificates = visible,
        count = create_cfe("count", tostring(#visible), "Certificates", "Number of certificates", "text"),
        filter = create_cfe(
            "filter", filter, "Filter", "Certificate filter", "select",
            {"all", "infrastructure", "ephemeral"}
        ),
        expired_window = create_cfe(
            "expired_window", expired_window, "Show expired", "How far back to show expired certs", "select",
            {"smart", "24h", "1w", "all"}
        ),
        db_exec_time = create_cfe(
            "db_exec_time", db_exec_time and string.format("%.4f", db_exec_time) or "",
            "DB Load Time", "Execution time of bulk loader", "text"
        )
    }
end

-- Private: query BadgerDB via step-badger and return the exact same structure as
-- list_certs_from_files so both paths are interchangeable.
list_certs_from_badger = function(clientdata)
    clientdata = clientdata or {}
    local filter         = clientdata.filter         or "all"
    local expired_window = clientdata.expired_window or "smart"

    local function empty_result(err_msg)
        return {
            error = err_msg and create_cfe("error", err_msg, "Error", "", "text") or nil,
            certificates = {},
            count        = create_cfe("count",  "0",    "Certificates",      "Number of certificates", "text"),
            filter       = create_cfe("filter", filter, "Filter",            "Certificate filter",     "select",
                {"all", "infrastructure", "ephemeral"}),
            db_exec_time = create_cfe("db_exec_time", "", "DB Load Time", "", "text"),
        }
    end

    if not file_exists(step_db_path) then
        return empty_result("Database not found at " .. step_db_path)
    end
    if not has_jq() then
        return empty_result("jq is required (not found in PATH)")
    end

    -- Slim the large JSON output to only the fields we need.
    -- jq -c '.[] | {...}' → one flat JSON object per line.
    local jq_filter = '.[] | {'
        .. '"cn":.Certificate.Subject.CommonName,'
        .. '"issuer":.Certificate.Issuer.CommonName,'
        .. '"not_before":.Certificate.NotBefore,'
        .. '"not_after":.Certificate.NotAfter,'
        .. '"validity":.Validity,'
        .. '"serial":.StringSerials.SerialDec,'
        .. '"is_ca":(.Certificate.IsCA | tostring),'
        .. '"eku":(.Certificate.ExtKeyUsage // [] | map(tostring) | join(","))'
        .. '}'

    local t0 = os.time()
    local full_cmd = string.format(
        "T=$(mktemp -d /tmp/step-badger.XXXXXX) && cp -r '%s'/* \"$T\"/ 2>/dev/null;"
        .. " export PATH='/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin';"
        .. " step-badger x509Certs \"$T\" -re --serial hex --emit json 2>/dev/null"
        .. " | jq -c '%s';"
        .. " rm -rf \"$T\"",
        step_db_path,
        jq_filter
    )
    local raw_output = exec_command(full_cmd)
    local exec_time  = os.time() - t0

    -- Extract a quoted string value from a compact JSON object line
    local function js(obj, key)
        return obj:match('"' .. key .. '":"([^"]*)"') or ""
    end

    -- Pass 1: parse all records and find the root CA CN (self-signed CA)
    local records  = {}
    local root_cn  = nil
    for line in raw_output:gmatch("[^\n]+") do
        if line:sub(1, 1) == "{" then
            local rec = {
                cn         = js(line, "cn"),
                issuer     = js(line, "issuer"),
                not_before = js(line, "not_before"),
                not_after  = js(line, "not_after"),
                validity   = js(line, "validity"),
                serial     = js(line, "serial"),
                is_ca      = (js(line, "is_ca") == "true"),
                eku        = js(line, "eku"),
            }
            if rec.cn ~= "" or rec.not_after ~= "" then
                table.insert(records, rec)
                if rec.is_ca and rec.cn == rec.issuer then
                    root_cn = rec.cn
                end
            end
        end
    end

    -- Pass 2: classify, compute status, apply filter
    local now   = os.time()
    local certs = {}

    for _, rec in ipairs(records) do
        -- Determine cert type matching detect_cert_type() labels exactly
        local cert_type, is_system
        if rec.is_ca then
            if rec.cn == rec.issuer then
                cert_type = "Root CA";         is_system = true
            elseif root_cn and rec.issuer == root_cn then
                cert_type = "Intermediate CA"; is_system = true
            else
                cert_type = "CA";              is_system = false
            end
        else
            local e = "," .. rec.eku .. ","
            local srv = e:find(",1,") ~= nil
            local clt = e:find(",2,") ~= nil
            if srv and clt then      cert_type = "Client-Server"
            elseif srv then          cert_type = "Server"
            elseif clt then          cert_type = "Client"
            else                     cert_type = "User Certificate"
            end
            is_system = false
        end

        -- Derive the filesystem cert_name used in action links
        local cert_name
        if cert_type == "Root CA" then
            cert_name = "root_ca"
        elseif cert_type == "Intermediate CA" then
            cert_name = "intermediate_ca"
        else
            cert_name = rec.cn
        end

        -- Compute days remaining and lifetime
        local start_epoch  = parse_date_to_epoch(rec.not_before)
        local finish_epoch = parse_date_to_epoch(rec.not_after)
        local days_remaining, total_lifetime_days
        if finish_epoch then
            days_remaining     = math.floor((finish_epoch - now) / 86400)
            if start_epoch then
                total_lifetime_days = math.floor((finish_epoch - start_epoch) / 86400)
            end
        end

        -- Status and color using the same logic as the file-based path
        local calc_status, color
        if rec.validity == "Revoked" then
            calc_status = "Revoked"; color = "red"
        else
            calc_status, color = get_expiration_status(days_remaining, cert_type, total_lifetime_days)
        end

        -- Apply filter.
        -- For CA certs always treat as infrastructure.
        -- For leaf certs use lifetime: > 29 days = infrastructure, else ephemeral.
        -- This lets short-lived Client-Server certs appear under the ephemeral filter.
        local is_infra
        if cert_type == "Root CA" or cert_type == "Intermediate CA" or cert_type == "CA" then
            is_infra = true
        elseif total_lifetime_days then
            is_infra = total_lifetime_days > 29
        else
            is_infra = is_infrastructure_cert(cert_type)
        end

        -- Type filter
        local type_ok
        if filter == "infrastructure" then     type_ok = is_infra
        elseif filter == "ephemeral" then      type_ok = not is_infra
        else                                   type_ok = true
        end

        -- Expired-window sub-filter
        local window_ok = show_expired(finish_epoch, total_lifetime_days, is_infra, expired_window)

        if type_ok and window_ok then
            local cert_path = step_certs_path .. "/" .. cert_name .. ".crt"
            table.insert(certs, {
                name = create_cfe("name", cert_name, "Certificate Name", "Certificate filename", "text"),
                subject = create_cfe("subject", rec.cn, "Common Name", "Certificate CN", "text"),
                serial = create_cfe("serial", rec.serial, "Serial Number", "Certificate serial number", "text"),
                cert_type = create_cfe("cert_type", cert_type, "Type", "Certificate type", "text"),
                is_system_cert = create_cfe("is_system_cert", tostring(is_system), "System Cert", "Managed", "text"),
                is_revoked = create_cfe("is_revoked",
                    tostring(rec.validity == "Revoked"), "Revoked", "Is revoked", "boolean"),
                path = create_cfe("path", cert_path, "File Path", "Path to file", "text"),
                days_remaining = create_cfe("days_remaining",
                    tostring(days_remaining or "N/A"), "Days Left", "Days left", "text"),
                expiration_date = create_cfe("expiration_date", rec.not_after, "Expiration", "Expiration date", "text"),
                status = create_cfe("status", calc_status, "Status", "Expiration/Revocation status", "text"),
                color = create_cfe("color", color, "Status Color", "Status indicator color", "text"),
            })
        end
    end

    -- Supplement with system CA certs (root_ca, intermediate_ca).
    -- These are created offline during CA init and are never written to BadgerDB.
    for _, sys_name in ipairs({"root_ca", "intermediate_ca"}) do
        local cert_file = step_certs_path .. "/" .. sys_name .. ".crt"
        if file_exists(cert_file) then
            local meta = get_cert_metadata(cert_file)
            if meta then
                local cert_type, is_system = detect_cert_type(cert_file, sys_name)
                local start_epoch  = parse_date_to_epoch(meta.not_before)
                local finish_epoch = parse_date_to_epoch(meta.not_after)
                local days_num, lifetime_days
                if finish_epoch then
                    days_num = math.floor((finish_epoch - now) / 86400)
                    if start_epoch then
                        lifetime_days = math.floor((finish_epoch - start_epoch) / 86400)
                    end
                end
                local calc_status, color = get_expiration_status(days_num, cert_type, lifetime_days)

                -- CA certs are always infrastructure; apply both type and window filters
                local type_ok  = (filter == "all") or (filter == "infrastructure")
                local window_ok = show_expired(finish_epoch, lifetime_days, true, expired_window)
                local include = type_ok and window_ok
                if include then
                    table.insert(certs, {
                        name = create_cfe("name", sys_name, "Certificate Name", "Certificate filename", "text"),
                        subject = create_cfe("subject",
                            meta.subject or sys_name, "Common Name", "Certificate CN", "text"),
                        serial = create_cfe("serial",
                            meta.serial or "", "Serial Number", "Certificate serial number", "text"),
                        cert_type = create_cfe("cert_type", cert_type, "Type", "Certificate type", "text"),
                        is_system_cert = create_cfe("is_system_cert", "true", "System Cert", "Managed", "text"),
                        is_revoked = create_cfe("is_revoked", "false", "Revoked", "Is revoked", "boolean"),
                        path = create_cfe("path", cert_file, "File Path", "Path to file", "text"),
                        days_remaining = create_cfe("days_remaining",
                            tostring(days_num or "N/A"), "Days Left", "Days left", "text"),
                        expiration_date = create_cfe("expiration_date",
                            meta.not_after or "", "Expiration", "Expiration date", "text"),
                        status = create_cfe("status", calc_status, "Status", "Expiration/Revocation status", "text"),
                        color = create_cfe("color", color, "Status Color", "Status indicator color", "text"),
                    })
                end
            end
        end
    end

    return {
        certificates = certs,
        count = create_cfe("count", tostring(#certs), "Certificates", "Number of certificates", "text"),
        filter = create_cfe("filter", filter, "Filter", "Certificate filter", "select",
            {"all", "infrastructure", "ephemeral"}),
        expired_window = create_cfe("expired_window", expired_window,
            "Show expired", "How far back to show expired certs", "select",
            {"smart", "24h", "1w", "all"}),
        db_exec_time = create_cfe("db_exec_time",
            string.format("%.1f", exec_time), "DB Load Time", "Execution time of bulk loader", "text"),
    }
end


-- Get certificate details
function mymodule.get_certificate_details(clientdata)
    local cert_name = clientdata.cert_name
    if not cert_name then
        return {error = create_cfe("error", "No certificate specified", "Error", "", "text")}
    end

    local cert_path = step_certs_path .. "/" .. cert_name .. ".crt"

    if not file_exists(cert_path) then
        return {error = create_cfe("error", "Certificate not found: " .. cert_name, "Error", "", "text")}
    end

    local details = {}
    details.cert_name = create_cfe("cert_name", cert_name, "Certificate Name", "", "text")

    -- Get full certificate inspection
    local inspect_cmd = "step certificate inspect " .. cert_path .. " 2>/dev/null"
    details.inspection = create_cfe(
        "inspection",
        exec_command(inspect_cmd),
        "Certificate Details",
        "",
        "longtext"
    )

    -- Get PEM content
    local pem_content = fs.read_file(cert_path)
    details.pem = create_cfe(
        "pem",
        pem_content,
        "PEM Content",
        "",
        "longtext"
    )

    -- Check for corresponding private key
    local key_path = step_certs_path .. "/" .. cert_name .. ".key"
    local has_key = file_exists(key_path)
    details.has_key = create_cfe(
        "has_key",
        tostring(has_key),
        "Private Key Available",
        "",
        "boolean"
    )

    return details
end

-- Export certificate for download (cert, key, or bundle)
-- Returns table with {content, filename} on success or {error} on failure
function mymodule.export_certificate(clientdata)
    local cert_name = clientdata.cert_name
    local type = clientdata.type or "cert"

    if not cert_name or cert_name == "" then
        return { error = create_cfe("error", "Certificate name is required", "Error", "", "text") }
    end

    -- Prevent path traversal
    if cert_name:match("/") or cert_name:match("%.%.") then
        return { error = create_cfe("error", "Invalid certificate name", "Error", "", "text") }
    end

    local cert_path = step_certs_path .. "/" .. cert_name .. ".crt"
    local key_path = step_certs_path .. "/" .. cert_name .. ".key"
    local content
    local filename = cert_name

    -- Check if this is a system cert
    local is_system_cert = (cert_name == "root_ca" or cert_name == "intermediate_ca")

    if type == "cert" then
        if not file_exists(cert_path) then
            return { error = create_cfe("error", "Certificate file not found", "Error", "", "text") }
        end
        -- We must read as step-ca user since nobody (web server) cannot read these files
        content = exec_as_stepca("cat " .. cert_path)
        filename = filename .. ".crt"

    elseif type == "key" then
        if is_system_cert then
            return { error = create_cfe("error", "System private keys are protected", "Error", "", "text") }
        end
        if not file_exists(key_path) then
            return { error = create_cfe("error", "Private key not found", "Error", "", "text") }
        end
        content = exec_as_stepca("cat " .. key_path)
        filename = filename .. ".key"

    elseif type == "bundle" then
        if is_system_cert then
            return { error = create_cfe("error", "System private keys are protected", "Error", "", "text") }
        end
        if not file_exists(cert_path) or not file_exists(key_path) then
            return { error = create_cfe("error", "Certificate or key not found", "Error", "", "text") }
        end
        local c = exec_as_stepca("cat " .. cert_path)
        local k = exec_as_stepca("cat " .. key_path)
        content = k .. "\n" .. c
        filename = filename .. ".pem"
    else
        return { error = create_cfe("error", "Invalid download type", "Error", "", "text") }
    end

    return {
        content = content,
        filename = filename
    }
end

-- Get certificate creation form
function mymodule.get_create_form(clientdata)
    local form = {}

    form.common_name = create_cfe(
        "common_name",
        clientdata.common_name or "",
        "Common Name (CN)",
        "Subject Common Name for the certificate",
        "text"
    )

    form.cert_profile = create_cfe(
        "cert_profile",
        clientdata.cert_profile or "leaf",
        "Certificate Profile",
        "Standard step-ca profile to use",
        "select",
        {"leaf", "intermediate-ca", "root-ca", "self-signed"}
    )

    -- Dynamic list of templates
    local templates = {"None"}
    local template_dir = step_ca_base .. "/templates"
    local template_output = exec_as_stepca("ls -1 " .. template_dir .. " 2>/dev/null")
    local found_templates = {}
    for filename in template_output:gmatch("[^\n]+") do
        filename = filename:match("^%s*(.-)%s*$")
        if filename ~= "" and (filename:lower():match("%.tpl$") or filename:lower():match("%.json$")) then
            table.insert(found_templates, filename)
        end
    end
    table.sort(found_templates)
    for _, t in ipairs(found_templates) do
        table.insert(templates, t)
    end

    form.cert_template = create_cfe(
        "cert_template",
        clientdata.cert_template or "None",
        "Certificate Template",
        "Optional template to augment the certificate",
        "select",
        templates
    )

    form.san_list = create_cfe(
        "san_list",
        clientdata.san_list or "",
        "Subject Alternative Names",
        "Comma-separated list of SANs (DNS names, IPs)",
        "text"
    )

    -- Dynamically get provisioners for the dropdown
    local prov_list = mymodule.list_provisioners()
    local prov_names = {}
    if prov_list.provisioners and #prov_list.provisioners > 0 then
        for _, prov in ipairs(prov_list.provisioners) do
            table.insert(prov_names, prov.name.value)
        end
    else
        table.insert(prov_names, "admin") -- Fallback
    end

    form.provisioner = create_cfe(
        "provisioner",
        clientdata.provisioner or prov_names[1],
        "Provisioner",
        "The provisioner to use for signing (for 'leaf' profile)",
        "select",
        prov_names
    )

    form.validity_days = create_cfe(
        "validity_days",
        clientdata.validity_days or "365",
        "Validity (Days)",
        "Certificate validity period in days",
        "text"
    )

    form.key_type = create_cfe(
        "key_type",
        clientdata.key_type or "EC/P-256",
        "Key Algorithm",
        "Key type and curve/size (EC recommended)",
        "select",
        {"EC/P-256", "EC/P-384", "EC/P-521", "RSA/2048", "RSA/4096", "RSA/8192", "OKP/Ed25519"}
    )

    return form
end

function mymodule.create_certificate(clientdata)
    local result = {}

    -- Validate required fields
    if not clientdata.common_name or clientdata.common_name == "" then
        result.error = create_cfe("error", "Common Name is required", "Error", "Validation error", "text")
        return result
    end

    local cn = clientdata.common_name
    local validation_error = validate_hostname(cn, "Common Name")
    if validation_error then
        result.error = create_cfe("error", validation_error, "Error", "Validation error", "text")
        return result
    end

    local step_status = exec_command("rc-service step-ca status 2>&1")
    local is_running = step_status:match("started")

    local validity_duration = (tonumber(clientdata.validity_days or 365) * 24) .. "h"
    local provisioner = clientdata.provisioner or "admin"
    local cert_profile = clientdata.cert_profile or "leaf"
    local cert_template = clientdata.cert_template or "None"
    local key_type = clientdata.key_type or "EC/P-256"

    local cert_path = step_certs_path .. "/" .. cn .. ".crt"
    local key_path = step_certs_path .. "/" .. cn .. ".key"

    -- Determine Track:
    -- base track: step certificate create (direct signing, supports --template)
    -- ca track:   step ca certificate (CA API, no --template flag)
    -- If a template is selected for a CA-track cert, switch to base track and sign
    -- directly with the intermediate CA — step ca certificate has no --template flag.
    local track = "ca"
    local actual_profile = cert_profile
    if cert_profile == "root-ca" or cert_profile == "intermediate-ca" then
        track = "base"
    elseif cert_template ~= "None" then
        track = "base"
    end

    -- Build flags table. Positionals ({cn, cert_path, key_path}) are passed
    -- separately to stepca_exec so build_step_args can guarantee flags-before-positionals.
    local flags = {}
    local exec_options = { use_pass = true, pass_flag = "--password-file", force = true }

    if track == "base" then
        -- LOW-LEVEL track: step certificate create
        if cert_template ~= "None" then
            table.insert(flags, string.format("--template='%s/templates/%s'", step_ca_base, cert_template))
        else
            table.insert(flags, string.format("--profile='%s'", actual_profile))
        end

        -- Point to the signing CA (root signs intermediate; intermediate signs leaf)
        if cert_profile == "intermediate-ca" then
            table.insert(flags, string.format("--ca='%s/certs/root_ca.crt'", step_ca_base))
            table.insert(flags, string.format("--ca-key='%s/secrets/root_ca_key'", step_ca_base))
            table.insert(flags, string.format("--ca-password-file='%s'", step_password_file))
        elseif cert_profile ~= "root-ca" then
            -- Leaf cert signed directly by intermediate CA
            table.insert(flags, string.format("--ca='%s/certs/intermediate_ca.crt'", step_ca_base))
            table.insert(flags, string.format("--ca-key='%s/secrets/intermediate_ca_key'", step_ca_base))
            table.insert(flags, string.format("--ca-password-file='%s'", step_password_file))
        end

        if cert_profile == "self-signed" then
            table.insert(flags, "--subtle")
        end
        table.insert(flags, string.format("--not-after='%s'", validity_duration))
        table.insert(flags, "--no-password")
        table.insert(flags, "--insecure")
    else
        -- CA track: step ca certificate
        if not is_running then
            table.insert(flags, "--offline")
            exec_options.pass_flag = "--password-file"
        else
            exec_options.pass_flag = "--provisioner-password-file"
        end

        table.insert(flags, string.format("--set=profile='%s'", actual_profile))
        table.insert(flags, string.format("--not-after='%s'", validity_duration))
        table.insert(flags, string.format("--provisioner='%s'", provisioner))
    end

    -- Key algorithm: --kty with --curve (EC/OKP) or --size (RSA)
    local kty, kparam = key_type:match("^([^/]+)/(.+)$")
    if kty == "RSA" then
        table.insert(flags, "--kty=RSA")
        table.insert(flags, string.format("--size=%s", kparam))
    elseif kty == "OKP" then
        table.insert(flags, "--kty=OKP")
        table.insert(flags, string.format("--curve=%s", kparam))
    elseif kty == "EC" and kparam ~= "P-256" then
        table.insert(flags, "--kty=EC")
        table.insert(flags, string.format("--curve=%s", kparam))
    end
    -- EC/P-256 is the step default; no flags needed

    -- SANs are flags too — must stay in the flags table (before positionals)
    local san = clientdata.san_list or ""
    if san ~= "" then
        for s in san:gmatch("[^,]+") do
            local trimmed = s:match("^%s*(.-)%s*$")
            table.insert(flags, string.format("--san='%s'", trimmed))
        end
    end

    local subaction = (track == "base") and "create" or "certificate"
    local output = stepca_exec(track, subaction, flags, {cn, cert_path, key_path}, exec_options)

    if file_exists(cert_path) then
        local msg = "Certificate created successfully"
        if track == "base" then
            msg = msg .. " (Direct Signing)"
        elseif not is_running then
            msg = msg .. " (Offline Mode)"
        end
        result.success = create_cfe("success", msg, "Success", "", "text")
        result.cert_path = create_cfe("cert_path", cert_path, "Certificate Path", "", "text")
        result.key_path = create_cfe("key_path", key_path, "Private Key Path", "", "text")
    else
        -- Clean up messy help output from step-cli
        local clean_output = output:gsub("NAME:.*", ""):gsub("USAGE:.*", "")
        clean_output = clean_output:gsub("OPTIONS:.*", ""):gsub("EXAMPLES:.*", ""):gsub("DESCRIPTION:.*", "")
        clean_output = clean_output:gsub("%[0;%d+;%d+m", ""):gsub("%[0m", "")


        result.error = create_cfe("error", "Certificate creation failed: " .. clean_output, "Error", "", "text")
    end

    return result
end

-- Get revoke form
function mymodule.get_revoke_form(clientdata)
    local form = {}

    form.serial = create_cfe(
        "serial",
        clientdata.serial or "",
        "Serial Number",
        "Certificate serial number to revoke",
        "text"
    )

    form.reason = create_cfe(
        "reason",
        clientdata.reason or "unspecified",
        "Revocation Reason",
        "Reason for revocation",
        "select",
        {
            "unspecified", "key-compromise", "ca-compromise", "affiliation-changed",
            "superseded", "cessation-of-operation"
        }
    )

    form.confirm = create_cfe(
        "confirm",
        clientdata.confirm or "",
        "Confirmation",
        "Type 'REVOKE' to confirm this destructive action",
        "text"
    )

    form.cert_name = create_cfe(
        "cert_name",
        clientdata.cert_name or "",
        "Certificate Name",
        "Certificate filename for reference",
        "text"
    )

    return form
end

-- Revoke certificate
function mymodule.revoke_certificate(clientdata)
    local result = {}

    -- Validation
    if clientdata.confirm ~= "REVOKE" then
        result.error = create_cfe(
            "error",
            "Confirmation required. Type 'REVOKE' to confirm.",
            "Error",
            "Error message",
            "text"
        )
        return result
    end

    if not clientdata.serial or clientdata.serial == "" then
        result.error = create_cfe(
            "error",
            "Serial number is required",
            "Error",
            "Error message",
            "text"
        )
        return result
    end

    local serial = clientdata.serial
    local reason = clientdata.reason or "unspecified"

    -- Map kebab-case reasons to camelCase format expected by step-ca
    local reason_map = {
        ["unspecified"] = "Unspecified",
        ["key-compromise"] = "KeyCompromise",
        ["ca-compromise"] = "CACompromise",
        ["affiliation-changed"] = "AffiliationChanged",
        ["superseded"] = "Superseded",
        ["cessation-of-operation"] = "CessationOfOperation"
    }
    local reason_code = reason_map[reason] or "Unspecified"

    -- Check service status to decide track
    local step_status = exec_command("rc-service " .. servicename .. " status 2>&1")
    local is_running = step_status:match("started")

    local output
    if is_running then
        -- ONLINE: Must generate a token first for non-interactive revocation
        local t_args = string.format("%s --revoke --provisioner=admin --password-file='%s'", serial, step_password_file)
        local token_cmd = string.format("STEPPATH='%s' step ca token %s 2>&1", step_ca_base, t_args)
        local raw_token = exec_as_stepca(token_cmd)
        -- Remove ANSI escape codes
        raw_token = raw_token:gsub("%[0;%d+;%d+m", ""):gsub("%[%d+m", ""):gsub("%[0m", "")

        -- Extract only the JWT (starts with ey and contains dots)
        local token = raw_token:match("(eyJ[%w%-_%.]+)") or ""

        if token ~= "" then
            -- POSITIONAL (serial) FIRST
            local rev_flags = {
                string.format("--token='%s'", token),
                string.format("--reasonCode=%s", reason_code),
            }
            output = stepca_exec("ca", "revoke", rev_flags, {serial}, { use_pass = false })
        else
            output = "Error generating revocation token: " .. raw_token
        end
    else
        -- OFFLINE: Access DB directly (safe because daemon is stopped)
        local rev_flags = {
            "--offline",
            string.format("--reasonCode=%s", reason_code),
        }
        output = stepca_exec("ca", "revoke", rev_flags, {serial}, { use_pass = true, pass_flag = "--password-file" })
    end

    -- Robust success detection (must not match help text)
    -- Look for the actual confirmation message from step CLI
    local is_success = output:match("Certificate with Serial Number.*has been revoked") or
                       output:match("Certificate with Serial Number.*is already revoked") or
                       (output:lower():match("success") and not output:lower():match("usage"))

    if is_success then
        -- Determine if this was a new revocation or already revoked
        local message = "Certificate revoked successfully"
        if output:lower():match("already") then
            message = "Certificate was already revoked"
        end

        result.success = create_cfe(
            "success",
            message,
            "Success",
            "Success message",
            "text"
        )

        -- Refresh CRL (run as step-ca user for proper ownership)
        exec_as_stepca("STEPPATH='" .. step_ca_base .. "' step ca crl " .. crl_path .. " 2>&1")

        result.log = create_cfe(
            "log",
            output,
            "Revocation Log",
            "Step-ca command output",
            "longtext"
        )
    else
        result.error = create_cfe(
            "error",
            "Revocation failed: " .. output,
            "Error",
            "Error message",
            "longtext"
        )
    end

    return result
end

-- ===========================================================================
-- Template Management
-- ===========================================================================

-- List template files
function mymodule.list_templates()
    local templates = {}
    local template_dir = step_ca_base .. "/templates"

    -- Ensure directory exists
    exec_as_stepca("mkdir -p " .. template_dir)

    local template_files = exec_as_stepca("ls -1 " .. template_dir .. " 2>/dev/null")
    for filename in template_files:gmatch("[^\n]+") do
        -- Trim only leading/trailing whitespace
        filename = filename:match("^%s*(.-)%s*$")
        if filename ~= "" and (filename:lower():match("%.tpl$") or filename:lower():match("%.json$")) then
            local path = template_dir .. "/" .. filename
            table.insert(templates, {
                name = create_cfe("name", filename, "Template Name", "", "text"),
                path = create_cfe("path", path, "File Path", "", "text")
            })
        end
    end

    -- Sort templates by name
    table.sort(templates, function(a, b) return a.name.value < b.name.value end)

    return {
        templates = templates,
        count = create_cfe("count", tostring(#templates), "Total Templates", "", "text")
    }
end

-- Form for adding a new template
function mymodule.get_add_template_form(clientdata)
    return {
        template_type = create_cfe(
            "template_type", clientdata.template_type or "x509", "Template Type",
            "Prefixes filename for organization", "select", {"x509", "ssh-user", "ssh-host", "none"}
        ),
        template_name = create_cfe(
            "template_name", "", "Template Name", "e.g., leaf.tpl (ends in .tpl or .json)", "text"
        ),
        content = create_cfe(
            "content", "{\n    \"subject\": {{ toJson .Subject }},\n    \"sans\": {{ toJson .SANs }}\n}",
            "Content", "", "longtext"
        )
    }
end

-- Get template details for editing
function mymodule.get_template_details(clientdata)
    local template_name = clientdata.template_name
    if not template_name then
        return {error = create_cfe("error", "No template specified", "Error", "", "text")}
    end

    local template_path = step_ca_base .. "/templates/" .. template_name
    if not file_exists(template_path) then
        return {error = create_cfe("error", "Template not found: " .. template_name, "Error", "", "text")}
    end

    local content = fs.read_file(template_path)
    return {
        template_name = create_cfe("template_name", template_name, "Template Name", "", "text"),
        content = create_cfe("content", content, "Template Content (JSON/Go Template)", "", "longtext")
    }
end

-- Save template content
function mymodule.save_template(clientdata)
    local template_name = clientdata.template_name
    local template_type = clientdata.template_type
    local content = clientdata.content

    -- Handle prefixing for NEW templates (if template_type is provided and name doesn't already have it)
    if template_type and template_type ~= "none" and template_name and template_name ~= "" then
        local prefix = template_type .. "-"
        if not template_name:match("^" .. prefix) then
            template_name = prefix .. template_name
        end
    end

    if not template_name or template_name == "" then
        return {
            template_type = create_cfe(
                "template_type", template_type or "x509", "Template Type", "", "select",
                {"x509", "ssh-user", "ssh-host", "none"}
            ),
            template_name = create_cfe("template_name", "", "Template Name", "", "text"),
            content = create_cfe("content", content or "", "Template Content", "", "longtext"),
            error = create_cfe("error", "Template name is missing", "Error", "", "text")
        }
    end

    local result = {
        template_name = create_cfe("template_name", template_name, "Template Name", "", "text"),
        content = create_cfe("content", content, "Template Content (JSON/Go Template)", "", "longtext")
    }

    -- Keep template_type in result for addtemplate re-rendering if needed
    if template_type then
        result.template_type = create_cfe(
            "template_type", template_type, "Template Type", "", "select",
            {"x509", "ssh-user", "ssh-host", "none"}
        )
    end

    local template_path = step_ca_base .. "/templates/" .. template_name

    -- Safety check: prevent path traversal
    if template_name:match("/") or template_name:match("%.%.") then
        result.error = create_cfe("error", "Invalid template name", "Error", "", "text")
        return result
    end

    -- JSON validation if file ends in .json
    if template_name:lower():match("%.json$") then
        local tmp_json = string.format("/tmp/step-json-validate-%d-%d.tmp", os.time(), math.random(1000, 9999))
        local fj = io.open(tmp_json, "w")
        if fj then
            fj:write(content)
            fj:close()
            local jq_res = exec_command("jq . " .. tmp_json .. " 2>&1")
            os.remove(tmp_json)
            if jq_res:lower():match("error") or jq_res:lower():match("parse") then
                -- Extract actual error message from jq
                local clean_err = jq_res:match("parse error: (.*)") or jq_res
                result.error = create_cfe("error", "Invalid JSON syntax: " .. clean_err, "Error", "", "text")
                return result
            end
        end
    end

    -- Save content using su to step-ca user
    local tmp_file = string.format("/tmp/step-template-%d-%d.tmp", os.time(), math.random(1000, 9999))
    local f = io.open(tmp_file, "w")
    if not f then
        result.error = create_cfe("error", "Failed to create temporary file", "Error", "", "text")
        return result
    end
    f:write(content or "")
    f:close()
    local cmd = string.format("cp '%s' '%s'", tmp_file, template_path)
    exec_as_stepca(cmd)
    os.remove(tmp_file)
    result.success = create_cfe("success", "Template '" .. template_name .. "' saved.", "Success", "", "text")

    return result
end

-- Delete template file
function mymodule.delete_template(clientdata)
    local result = {}
    local template_name = clientdata.template_name

    if not template_name or template_name == "" then
        result.error = create_cfe("error", "Template name is missing", "Error", "", "text")
        return result
    end

    local template_path = step_ca_base .. "/templates/" .. template_name

    -- Safety check
    if template_name:match("/") or template_name:match("%.%.") then
        result.error = create_cfe("error", "Invalid template name", "Error", "", "text")
        return result
    end

    if not file_exists(template_path) then
        result.error = create_cfe("error", "Template not found", "Error", "", "text")
        return result
    end

    local cmd = string.format("rm '%s'", template_path)
    local output = exec_as_stepca(cmd)

    result.success = create_cfe("success", "Template '" .. template_name .. "' deleted.", "Success", "", "text")
    return result
end

-- ===========================================================================
-- Provisioner Management Functions
-- ===========================================================================

-- List provisioners from step-ca configuration
function mymodule.list_provisioners()
    local provisioners = {}

    if not file_exists(step_config) then
        return {
            error = create_cfe("error", "CA configuration not found", "Error", "", "text"),
            provisioners = {}
        }
    end

    -- Read and parse ca.json
    local config_content = fs.read_file(step_config)

    -- Extract provisioners array from JSON (robust parsing with brace depth tracking)
    local in_provisioners = false
    local provisioner_data = {}
    local current_prov = {}
    local brace_level = 0

    for line in config_content:gmatch("[^\n]+") do
        if not in_provisioners then
            if line:match('"provisioners"%s*:%s*%[') then
                in_provisioners = true
                brace_level = 0
            end
        else
            -- Count braces to track nesting depth
            if line:match("{") then brace_level = brace_level + 1 end

            -- Only capture name/type at the top level of the provisioner object
            if brace_level == 1 then
                local p_type = line:match('"type"%s*:%s*"([^"]+)"')
                if p_type then current_prov.type = p_type end
                local p_name = line:match('"name"%s*:%s*"([^"]+)"')
                if p_name then current_prov.name = p_name end
            end

            if line:match("}") then
                brace_level = brace_level - 1
                -- At the end of a top-level provisioner object, save it
                if brace_level == 0 and current_prov.name then
                    table.insert(provisioner_data, {
                        name = current_prov.name,
                        type = current_prov.type or "Unknown"
                    })
                    current_prov = {}
                end
            end

            -- End of provisioners array
            if brace_level == 0 and line:match("%]") then
                in_provisioners = false
            end
        end
    end

    -- Convert to CFE format
    for _, prov in ipairs(provisioner_data) do
        local description, icon

        if prov.type == "JWK" then
            description = "JSON Web Key - Password-based authentication"
            icon = "🔑"
        elseif prov.type == "OIDC" then
            description = "OpenID Connect - OAuth2/OIDC authentication"
            icon = "🌐"
        elseif prov.type == "ACME" then
            description = "Automated Certificate Management Environment"
            icon = "🤖"
        elseif prov.type == "SCEP" then
            description = "Simple Certificate Enrollment Protocol - for network devices"
            icon = "📡"
        elseif prov.type == "SSHPOP" then
            description = "SSH Proof of Possession - X.509 certs from SSH keys"
            icon = "🔐"
        else
            description = "Other provisioner type"
            icon = "❓"
        end

        table.insert(provisioners, {
            name = create_cfe("name", prov.name, "Name", "Provisioner name", "text"),
            type = create_cfe("type", prov.type, "Type", "Provisioner type", "text"),
            description = create_cfe("description", description, "Description", "Provisioner description", "text"),
            icon = create_cfe("icon", icon, "Icon", "Visual indicator", "text")
        })
    end

    return {
        provisioners = provisioners,
        count = create_cfe(
            "count", tostring(#provisioners), "Total Provisioners",
            "Number of configured provisioners", "text"
        )
    }
end

-- Get add provisioner form
function mymodule.get_add_provisioner_form(clientdata)
    local form = {}

    form.prov_type = create_cfe(
        "prov_type",
        clientdata.prov_type or "OIDC",
        "Provisioner Type",
        "Type of provisioner to add",
        "select",
        {"OIDC", "ACME", "JWK", "SCEP", "SSHPOP"}
    )

    form.prov_name = create_cfe(
        "prov_name",
        clientdata.prov_name or "",
        "Provisioner Name",
        "Unique name for this provisioner (e.g., 'kanidm', 'letsencrypt', 'switches')",
        "text"
    )

    -- SCEP-specific fields
    form.scep_challenge = create_cfe(
        "scep_challenge",
        clientdata.scep_challenge or "",
        "SCEP Challenge Password",
        "The shared secret used by devices to enroll (OTP)",
        "password"
    )

    -- OIDC-specific fields
    form.client_id = create_cfe(
        "client_id",
        clientdata.client_id or "",
        "Client ID",
        "OAuth2 Client ID from your identity provider",
        "text"
    )

    form.client_secret = create_cfe(
        "client_secret",
        clientdata.client_secret or "",
        "Client Secret",
        "OAuth2 Client Secret from your identity provider",
        "password"
    )

    form.config_endpoint = create_cfe(
        "config_endpoint",
        clientdata.config_endpoint or "",
        "Configuration Endpoint",
        "OIDC discovery URL (e.g., https://kanidm.example.com/oauth2/openid/step-ca/.well-known/openid-configuration)",
        "text"
    )

    form.listen_address = create_cfe(
        "listen_address",
        clientdata.listen_address or ":10000",
        "Listen Address",
        "Local address for OIDC callback (default :10000)",
        "text"
    )

    -- Dynamic list of templates for provisioners
    local x509_templates = {"None"}
    local ssh_templates = {"None"}
    local template_dir = step_ca_base .. "/templates"
    local template_output = exec_as_stepca("ls -1 " .. template_dir .. " 2>/dev/null")

    local found_x509 = {}
    local found_ssh = {}

    for filename in template_output:gmatch("[^\n]+") do
        filename = filename:match("^%s*(.-)%s*$")
        if filename ~= "" and (filename:lower():match("%.tpl$") or filename:lower():match("%.json$")) then
            if filename:lower():match("^x509%-") then
                table.insert(found_x509, filename)
            elseif filename:lower():match("^ssh%-") then
                table.insert(found_ssh, filename)
            else
                -- If no prefix, add to both for maximum flexibility
                table.insert(found_x509, filename)
                table.insert(found_ssh, filename)
            end
        end
    end

    table.sort(found_x509)
    table.sort(found_ssh)

    for _, t in ipairs(found_x509) do table.insert(x509_templates, t) end
    for _, t in ipairs(found_ssh) do table.insert(ssh_templates, t) end

    form.x509_template = create_cfe(
        "x509_template",
        clientdata.x509_template or "None",
        "X.509 Certificate Template",
        "Optional template for X.509 certificates",
        "select",
        x509_templates
    )

    form.ssh_template = create_cfe(
        "ssh_template",
        clientdata.ssh_template or "None",
        "SSH Certificate Template",
        "Optional template for SSH certificates",
        "select",
        ssh_templates
    )

    -- Indicate whether SSH CA keys exist (required for SSHPOP provisioner)
    local has_ssh = file_exists(step_ca_base .. "/certs/ssh_user_ca_key.pub")
    form.has_ssh = create_cfe(
        "has_ssh",
        tostring(has_ssh),
        "SSH CA Available",
        "Whether the CA was initialized with SSH support (required for SSHPOP)",
        "text"
    )

    return form
end

-- Add a new provisioner
function mymodule.add_provisioner(clientdata)
    local result = {}
    -- Keep debug info for troubleshooting
    result.debug_cmd = create_cfe("debug_cmd", "Initializing provisioner creation...", "Debug", "", "longtext")

    -- Clean inputs (trim whitespace)
    local prov_name = (clientdata.prov_name or ""):gsub("^%s*(.-)%s*$", "%1")
    local client_id = (clientdata.client_id or ""):gsub("^%s*(.-)%s*$", "%1")
    local client_secret = (clientdata.client_secret or ""):gsub("^%s*(.-)%s*$", "%1")
    local config_endpoint = (clientdata.config_endpoint or ""):gsub("^%s*(.-)%s*$", "%1")

    -- Validate inputs
    if prov_name == "" then
        result.error = create_cfe("error", "Provisioner name is required", "Error", "", "text")
        return result
    end

    -- Validation: OIDC needs specific fields
    if clientdata.prov_type == "OIDC" then
        if client_id == "" then
            result.error = create_cfe("error", "Client ID is required for OIDC provisioner", "Error", "", "text")
            return result
        end
        if config_endpoint == "" then
            result.error = create_cfe("error",
                "Configuration Endpoint is required for OIDC provisioner", "Error", "", "text")
            return result
        end
    end

    -- Validation: SSHPOP requires SSH CA keys (only exist when CA was inited with --ssh)
    if clientdata.prov_type == "SSHPOP" then
        local ssh_user_ca_pub = step_ca_base .. "/certs/ssh_user_ca_key.pub"
        if not file_exists(ssh_user_ca_pub) then
            result.error = create_cfe(
                "error",
                "SSHPOP requires SSH CA support, but no SSH CA keys were found.\n\n"
                .. "The CA must be re-initialized with 'Enable SSH Certificate Authority' checked.\n"
                .. "SSH CA keys are created by step ca init --ssh and cannot be added after the fact.",
                "Error", "", "text"
            )
            return result
        end
    end

    -- 1. Setup Password and Keys based on type
    local prov_password = nil
    local args = string.format(" --ca-config='%s' ", step_config)

    if clientdata.prov_type == "JWK" then
        -- JWK requires special handling to bypass TTY prompts during key generation
        prov_password = exec_command("cat /proc/sys/kernel/random/uuid | sed 's/-//g'"):gsub("%s+", "")
        local pass_path = step_secrets_path .. "/provisioner_" .. prov_name .. ".pass"

        -- Save the password securely first
        local f_pass = io.open("/tmp/prov_pass.tmp", "w")
        if f_pass then f_pass:write(prov_password) f_pass:close() end
        local cp_cmd = string.format(
            "cp /tmp/prov_pass.tmp %s && chown %s:%s %s && chmod 600 %s && rm /tmp/prov_pass.tmp",
            pass_path, get_stepca_user(), get_stepca_user(), pass_path, pass_path)
        exec_command(cp_cmd)

        -- Use the standard 'step ca provisioner add' with --create
        -- Providing --password-file here is the key to preventing the prompt during key creation
        args = args .. string.format("--type JWK --create --password-file='%s' ", pass_path)

    elseif clientdata.prov_type == "OIDC" then
        local listen_address = (clientdata.listen_address or ""):gsub("^%s*(.-)%s*$", "%1")
        args = args .. string.format("--type OIDC --client-id '%s' --configuration-endpoint '%s' ",
            client_id, config_endpoint)
        if client_secret ~= "" then
            args = args .. string.format("--client-secret '%s' ", client_secret:gsub("'", "'\\''"))
        end
        if listen_address ~= "" then
            args = args .. string.format("--listen-address '%s' ", listen_address)
        end

    elseif clientdata.prov_type == "ACME" then
        args = args .. "--type ACME "

    elseif clientdata.prov_type == "SCEP" then
        args = args .. "--type SCEP "
        if clientdata.scep_challenge and clientdata.scep_challenge ~= "" then
            args = args .. string.format("--challenge '%s' ", clientdata.scep_challenge:gsub("'", "'\\''"))
        end

    elseif clientdata.prov_type == "SSHPOP" then
        args = args .. "--type SSHPOP "
    end

    -- Add templates if selected
    if clientdata.x509_template and clientdata.x509_template ~= "None" then
        args = args .. string.format(" --x509-template='%s/templates/%s' ", step_ca_base, clientdata.x509_template)
    end
    if clientdata.ssh_template and clientdata.ssh_template ~= "None" then
        args = args .. string.format(" --ssh-template='%s/templates/%s' ", step_ca_base, clientdata.ssh_template)
    end

    -- Add the NAME as the ONLY positional argument
    args = args .. string.format("'%s'", prov_name)

    local final_cmd = "step ca provisioner add " .. args
    local output = exec_as_stepca(final_cmd .. " 2>&1")

    -- Capture debug state
    result.debug_cmd.value = "Internal Command: " .. final_cmd .. "\nOutput: " .. output

    -- 4. Verify Success
    local grep_check = string.format("grep -q '\"name\":%s\"%s\"' %s; echo $?", "%s*", prov_name, step_config)
    local is_success = output:lower():match("success") or output == "" or
                       exec_command(grep_check):match("0")

    if is_success then
        -- Persistent password storage for admin recovery
        if prov_password then
            local pass_path = step_secrets_path .. "/provisioner_" .. prov_name .. ".pass"
            local f = io.open(pass_path, "w")
            if f then f:write(prov_password) f:close() end
            local chown_cmd = string.format("chown %s:%s %s && chmod 600 %s",
                get_stepca_user(), get_stepca_user(), pass_path, pass_path)
            exec_command(chown_cmd)
            result.prov_password = create_cfe(
                "prov_password", prov_password, "Password", "SAVE THIS PASSWORD NOW.", "text"
            )
        end
        local step_status = exec_command("rc-service " .. servicename .. " status 2>&1")
        result.success = create_cfe(
            "success", "Provisioner '" .. prov_name .. "' added.", "Success", "", "text")
        result.is_running = step_status:match("started")
        result.restart_required = true
    else
        -- Clean output of ANSI colors and excessive whitespace
        local clean_output = output:gsub("%[%d+;%d+;%d+m", ""):gsub("%[%d+;%d+m", "")
        clean_output = clean_output:gsub("%[%d+m", ""):gsub("%[0m", "")
        clean_output = clean_output:gsub("^%s+", ""):gsub("%s+$", "")
        result.error = create_cfe("error", "Failed to add provisioner: " .. clean_output, "Error", "", "text")
    end

    return result
end

-- Delete a provisioner
function mymodule.delete_provisioner(clientdata)
    local result = {}
    local name = clientdata.prov_name

    if not name or name == "" then
        result.error = create_cfe("error", "Provisioner name is required", "Error", "", "text")
        return result
    end

    if not has_jq() then
        result.error = create_cfe("error", "The 'jq' package is required for management.", "Error", "", "text")
        return result
    end

    -- Surgical removal via jq
    local filter = string.format('del(.authority.provisioners[] | select(.name == "%s"))', name)
    local tmp_file = "/tmp/ca.json.tmp"
    local cmd = string.format(
        "jq '%s' %s > %s && mv %s %s 2>/dev/null", filter, step_config, tmp_file, tmp_file, step_config)
    exec_as_stepca(cmd)

    -- Verify removal
    local check_cmd = string.format(
        "jq -r '.authority.provisioners[] | select(.name == \"%s\") | .name' %s", name, step_config)
    local check_output = exec_command(check_cmd):gsub("%s+", "")

    if check_output == "" then
        -- Check service status for context-specific feedback
        local step_status = exec_command("rc-service " .. servicename .. " status 2>&1")
        local is_running = step_status:match("started")

        local success_msg = string.format("Provisioner '%s' removed successfully from ca.json.", name)
        if is_running then
            success_msg = success_msg .. " Restart or reload step-ca service to apply changes."
        else
            success_msg = success_msg .. " The service is currently stopped; changes will take effect when it starts."
        end

        result.success = create_cfe("success", success_msg, "Success", "", "text")
        result.is_running = is_running
        result.restart_required = true
    else
        local err = string.format("Failed to remove '%s'. Entry still exists in ca.json.", name)
        result.error = create_cfe("error", err, "Error", "", "text")
    end

    return result
end

-- Get CA hierarchy
function mymodule.get_ca_hierarchy()
    local hierarchy = {}

    -- Read root CA
    if file_exists(step_certs_path .. "/root_ca.crt") then
        hierarchy.root_ca = create_cfe(
            "root_ca",
            exec_command("step certificate inspect " .. step_certs_path .. "/root_ca.crt 2>/dev/null"),
            "Root CA",
            "Root Certificate Authority",
            "longtext"
        )
    end

    -- Read intermediate CA if exists
    if file_exists(step_certs_path .. "/intermediate_ca.crt") then
        hierarchy.intermediate_ca = create_cfe(
            "intermediate_ca",
            exec_command(
                "step certificate inspect " .. step_certs_path .. "/intermediate_ca.crt 2>/dev/null"
            ),
            "Intermediate CA",
            "Intermediate Certificate Authority",
            "longtext"
        )
    end

    return hierarchy
end

-- Get CRL info
function mymodule.get_crl_info()
    local crl_info = {}

    -- Note: This step-ca installation uses BadgerDB for revocation tracking
    -- CRL files are not generated by default
    crl_info.info = create_cfe(
        "info",
        "This CA uses BadgerDB and step-badger to track revocations. CRL files are not generated.",
        "Revocation Tracking",
        "How revocations are tracked",
        "longtext"
    )

    -- Query BadgerDB for revoked certificates using centralized helper
    local query_result = query_revoked_certificates()

    if query_result.success then
        if query_result.data and query_result.data ~= "" then
            crl_info.revoked_list = create_cfe(
                "revoked_list",
                query_result.data,
                "Revoked Certificates",
                "R, expiry, revoke_date, serial, reason, subject",
                "longtext"
            )
        else
            crl_info.no_revocations = create_cfe(
                "no_revocations",
                "No certificates have been revoked yet.",
                "Status",
                "Revocation status",
                "text"
            )
        end
    else
        crl_info.error = create_cfe(
            "error",
            query_result.error or "Unable to query revocation database",
            "Error",
            "Database error",
            "text"
        )
    end

    return crl_info
end

-- Refresh CRL (not applicable for BadgerDB-based tracking)
function mymodule.refresh_crl()
    local result = {}

    -- Query BadgerDB for revoked certificates using centralized helper
    local query_result = query_revoked_certificates()

    if query_result.success then
        if query_result.data and query_result.data ~= "" then
            -- Count the number of revoked certificates
            local count = 0
            for _ in query_result.data:gmatch("[^\n]+") do
                count = count + 1
            end

            result.success = create_cfe(
                "success",
                "Revocation list refreshed. Found " .. count .. " revoked certificate(s).",
                "Success",
                "Refresh status",
                "text"
            )

            result.revoked_list = create_cfe(
                "revoked_list",
                query_result.data,
                "Revoked Certificates",
                "Format: R, expiry, revoke_date, serial, reason, subject",
                "longtext"
            )
        else
            result.success = create_cfe(
                "success",
                "Revocation list refreshed. No revoked certificates found.",
                "Success",
                "Refresh status",
                "text"
            )

            result.no_revocations = create_cfe(
                "no_revocations",
                "No certificates have been revoked yet.",
                "Status",
                "Revocation status",
                "text"
            )
        end
    else
        result.error = create_cfe(
            "error",
            query_result.error or "Unable to query revocation database",
            "Error",
            "Database error",
            "text"
        )
    end

    return result
end


-- List client certificates
function mymodule.list_clients()
    local clients = {}

    -- Find client certificates (exclude server, CA, and webui certs)
    local cert_files = exec_command(
        "ls -1 " .. step_certs_path .. "/*-client.crt " .. step_certs_path .. "/client*.crt 2>/dev/null")

    for cert_file in cert_files:gmatch("[^\n]+") do
        local cert_name = cert_file:match("([^/]+)%.crt$")
        if cert_name then
            -- Get certificate expiration
            local expiry_cmd = "step certificate inspect " .. cert_file ..
                " --format json 2>/dev/null | grep -o '\"not_after\":\"[^\"]*\"'"
            local expiry = exec_command(expiry_cmd)

            table.insert(clients, {
                name = create_cfe(cert_name, "Client Name"),
                path = create_cfe(cert_file, "Certificate Path"),
                expiry = create_cfe(expiry, "Expiration")
            })
        end
    end

    return {
        clients = clients,
        count = create_cfe(tostring(#clients), "Total Clients")
    }
end

-- Get configuration (PKI parts)
function mymodule.get_config()
    local config = {}

    -- Read current thresholds from config file or use defaults
    local thresholds = get_thresholds_from_config()

    -- Infrastructure thresholds (days)
    config.critical_days = create_cfe(
        "critical_days",
        tostring(thresholds.critical_days),
        "Infrastructure: Critical Threshold (days)",
        "Infrastructure certs (CA, Server, Client) expiring within this many days are marked as CRITICAL (🔴)",
        "text"
    )

    config.warning_days = create_cfe(
        "warning_days",
        tostring(thresholds.warning_days),
        "Infrastructure: Warning Threshold (days)",
        "Infrastructure certs expiring within this many days are marked as WARNING (🟡)",
        "text"
    )

    config.notice_days = create_cfe(
        "notice_days",
        tostring(thresholds.notice_days),
        "Infrastructure: Notice Threshold (days)",
        "Infrastructure certs expiring within this many days show advance notice (🔵)",
        "text"
    )

    -- Ephemeral thresholds (percentages)
    config.critical_percent = create_cfe(
        "critical_percent",
        tostring(thresholds.critical_percent),
        "Ephemeral: Critical Threshold (%)",
        "Ephemeral certs (WiFi, IoT) with ≤ this % of lifetime remaining are marked as CRITICAL (🔴)",
        "text"
    )

    config.warning_percent = create_cfe(
        "warning_percent",
        tostring(thresholds.warning_percent),
        "Ephemeral: Warning Threshold (%)",
        "Ephemeral certs with ≤ this % of lifetime remaining are marked as WARNING (🟡)",
        "text"
    )

    config.notice_percent = create_cfe(
        "notice_percent",
        tostring(thresholds.notice_percent),
        "Ephemeral: Notice Threshold (%)",
        "Ephemeral certs with ≤ this % of lifetime remaining show advance notice (🔵)",
        "text"
    )

    -- Network configuration from ca.json
    local ca_dns = ""
    local ca_addr = ""
    if posix.stat(step_config) ~= nil then
        if has_jq() then
            ca_dns = exec_command("jq -r '.dnsNames[0] // \"\"' " .. step_config):gsub("%s+", "")
            ca_addr = exec_command("jq -r '.address // \"\"' " .. step_config):gsub("%s+", "")
        else
            local content = fs.read_file(step_config)
            ca_dns = content:match('"dnsNames"%s*:%s*%[%s*"([^"]+)"') or ""
            ca_addr = content:match('"address"%s*:%s*"([^"]+)"') or ""
        end
    end

    -- Clean up null values from jq
    if ca_dns == "null" then ca_dns = "" end
    if ca_addr == "null" then ca_addr = "" end

    config.ca_dns = create_cfe(
        "ca_dns",
        ca_dns,
        "CA DNS Name",
        "The primary DNS name for the CA server (stored in ca.json)",
        "text"
    )

    config.ca_address = create_cfe(
        "ca_address",
        ca_addr,
        "CA Listening Address",
        "The address and port the CA listens on, e.g., :443 or 0.0.0.0:443 (stored in ca.json)",
        "text"
    )

    return config
end

-- Save configuration
function mymodule.save_config(clientdata)
    -- Read all 6 threshold values
    local critical_days = tonumber(clientdata.critical_days) or 7
    local warning_days = tonumber(clientdata.warning_days) or 30
    local notice_days = tonumber(clientdata.notice_days) or 90
    local critical_percent = tonumber(clientdata.critical_percent) or 10
    local warning_percent = tonumber(clientdata.warning_percent) or 30
    local notice_percent = tonumber(clientdata.notice_percent) or 50

    -- Get the config form
    local result = mymodule.get_config()

    -- Validate infrastructure thresholds (days)
    if critical_days < 1 or critical_days > 365 then
        result.error = create_cfe("error", "Infrastructure Critical must be 1-365 days", "Error", "", "text")
        return result
    end

    if warning_days < critical_days or warning_days > 365 then
        result.error = create_cfe("error", "Infrastructure Warning must be > critical days", "Error", "", "text")
        return result
    end

    if notice_days < warning_days or notice_days > 365 then
        result.error = create_cfe("error", "Infrastructure Notice must be > warning days", "Error", "", "text")
        return result
    end

    -- Validate ephemeral thresholds (percentages)
    if critical_percent < 1 or critical_percent > 100 then
        result.error = create_cfe("error", "Ephemeral Critical must be 1-100%", "Error", "", "text")
        return result
    end

    if warning_percent < critical_percent or warning_percent > 100 then
        result.error = create_cfe("error", "Ephemeral Warning must be > critical %", "Error", "", "text")
        return result
    end

    if notice_percent < warning_percent or notice_percent > 100 then
        result.error = create_cfe("error", "Ephemeral Notice must be > warning %", "Error", "", "text")
        return result
    end

    -- Update ca.json if network settings changed (requires jq)
    if has_jq() and posix.stat(step_config) ~= nil then
        local current_dns = exec_command("jq -r '.dnsNames[0]' " .. step_config):gsub("%s+", "")
        local current_addr = exec_command("jq -r '.address' " .. step_config):gsub("%s+", "")

        local new_dns = clientdata.ca_dns or current_dns
        local new_addr = clientdata.ca_address or current_addr

        if new_dns ~= current_dns or new_addr ~= current_addr then
            local filter = string.format('.dnsNames[0] = "%s" | .address = "%s"', new_dns, new_addr)
            local tmp_file = "/tmp/ca.json.net.tmp"
            local cmd = string.format(
                "jq '%s' %s > %s && mv %s %s 2>/dev/null", filter, step_config, tmp_file, tmp_file, step_config)
            exec_as_stepca(cmd)
            result.ca_dns.value = new_dns
            result.ca_address.value = new_addr
            result.restart_required = true
        end
    end

    -- Write configuration file with all 6 thresholds
    local config_content = string.format([[# ACF Configuration for step-ca

# Infrastructure certificate expiration thresholds (in days for CA, Server, Client, Client-Server)
CRITICAL_DAYS=%d
WARNING_DAYS=%d
NOTICE_DAYS=%d

# Ephemeral certificate expiration thresholds (percentage of total lifetime for WiFi, IoT, short-lived)
CRITICAL_PERCENT=%d
WARNING_PERCENT=%d
NOTICE_PERCENT=%d

# Service user for step-ca daemon (matches /etc/init.d/step-ca command_user)
STEPCA_USER=step-ca
]],
        critical_days, warning_days, notice_days,
        critical_percent, warning_percent, notice_percent
    )

    local f = io.open(acf_config_file, "w")
    if f then
        f:write(config_content)
        f:close()
        result.success = create_cfe("success", "Configuration saved successfully", "Success", "", "text")
        -- Update the form values with the saved values (all 6 thresholds)
        result.critical_days.value = tostring(critical_days)
        result.warning_days.value = tostring(warning_days)
        result.notice_days.value = tostring(notice_days)
        result.critical_percent.value = tostring(critical_percent)
        result.warning_percent.value = tostring(warning_percent)
        result.notice_percent.value = tostring(notice_percent)
    else
        result.error = create_cfe("error", "Failed to write configuration file", "Error", "", "text")
    end

    return result
end

-- Get audit log (PKI parts)
function mymodule.get_audit_log(clientdata)
    local log = {}

    local lines = clientdata.lines or "100"

    -- Get step-ca logs (from journald or syslog)
    local log_output = exec_command("tail -n " .. lines .. " /var/log/step-ca.log 2>/dev/null")
    log.step_log = create_cfe(
        log_output,
        "step-ca Log",
        "Recent certificate authority operations",
        "longtext"
    )

    return log
end

-- ===========================================================================
-- First-Time Setup Wizard Functions
-- ===========================================================================

-- Check if CA is initialized
function mymodule.is_ca_initialized()
    return posix.stat(step_config) ~= nil
end

-- Get CA setup form
function mymodule.get_setup_form(clientdata)
    local form = {}

    -- Ensure clientdata exists
    clientdata = clientdata or {}

    -- Get hostname from system for default CN
    local hostname = exec_command("hostname -f 2>/dev/null"):gsub("%s+", "")
    if hostname == "" then
        hostname = exec_command("hostname 2>/dev/null"):gsub("%s+", "")
    end
    if hostname == "" then
        hostname = "pki-server.local"
    end

    form.ca_name = create_cfe(
        "ca_name",
        clientdata.ca_name or "PKI-Server",
        "CA Name",
        "Friendly name for your Certificate Authority",
        "text"
    )

    form.ca_common_name = create_cfe(
        "ca_common_name",
        clientdata.ca_common_name or hostname,
        "CA Common Name (CN)",
        "DNS name or IP address for the CA server",
        "text"
    )

    form.ca_port = create_cfe(
        "ca_port",
        clientdata.ca_port or default_port,
        "CA Port",
        "The port step-ca will listen on (default " .. default_port .. ", use 443 for standard HTTPS)",
        "text"
    )

    form.ca_organization = create_cfe(
        "ca_organization",
        clientdata.ca_organization or "Organization",
        "Organization (O)",
        "Your organization name",
        "text"
    )

    form.ca_organizational_unit = create_cfe(
        "ca_organizational_unit",
        clientdata.ca_organizational_unit or "IT",
        "Organizational Unit (OU)",
        "Department or unit name (optional)",
        "text"
    )

    form.ca_locality = create_cfe(
        "ca_locality",
        clientdata.ca_locality or "",
        "Locality/City (L)",
        "City or locality (optional)",
        "text"
    )

    form.ca_state = create_cfe(
        "ca_state",
        clientdata.ca_state or "",
        "State/Province (ST)",
        "State or province (optional)",
        "text"
    )

    form.ca_country = create_cfe(
        "ca_country",
        clientdata.ca_country or "US",
        "Country (C)",
        "Two-letter country code (e.g., US, CA, GB)",
        "text"
    )

    form.ca_email = create_cfe(
        "ca_email",
        clientdata.ca_email or "",
        "Email Address",
        "Contact email for CA administrator (optional)",
        "text"
    )

    form.ca_validity_years = create_cfe(
        "ca_validity_years",
        clientdata.ca_validity_years or "10",
        "Root CA Validity (Years)",
        "How long the root CA certificate is valid (typically 10-20 years)",
        "text"
    )

    form.ca_provisioner = create_cfe(
        "ca_provisioner",
        clientdata.ca_provisioner or "admin",
        "Provisioner Name",
        "Name for the default certificate provisioner",
        "text"
    )

    form.enable_ssh = create_cfe(
        "enable_ssh",
        false,
        "Enable SSH Certificate Authority",
        "Generate SSH CA keys so this CA can sign SSH host and user certificates",
        "boolean"
    )

    form.gen_intermediate = create_cfe(
        "gen_intermediate",
        true,
        "Generate Intermediate CA",
        "Create an intermediate CA (recommended for security)",
        "boolean"
    )

    form.intermediate_validity_years = create_cfe(
        "intermediate_validity_years",
        clientdata.intermediate_validity_years or "5",
        "Intermediate CA Validity (Years)",
        "How long the intermediate CA is valid (typically half of root CA)",
        "text"
    )

    form.instructions = create_cfe(
        "instructions",
        "Welcome to PKI Manager Initial Setup!\n\n" ..
        "You're about to initialize a new Certificate Authority. This wizard will:\n" ..
        "1. Create a Root CA with your specified details\n" ..
        "2. Optionally create an Intermediate CA (recommended)\n" ..
        "3. Generate a secure CA password and display it for you to save\n\n" ..
        "IMPORTANT: The CA password will be shown ONCE. You must save it securely!",
        "Setup Instructions",
        "",
        "longtext"
    )

    return form
end

-- Initialize CA with password generation and display
function mymodule.initialize_ca(clientdata)
    local result = {}

    -- Check if already initialized
    if mymodule.is_ca_initialized() then
        result.error = create_cfe("error", "CA is already initialized!", "Error", "", "error")
        return result
    end

    -- Get configuration from clientdata (submitted form)
    local ca_name = clientdata.ca_name or "PKI-Server"
    local ca_common_name = clientdata.ca_common_name or ""
    local ca_organization = clientdata.ca_organization or "Organization"
    local ca_organizational_unit = clientdata.ca_organizational_unit or ""
    local ca_locality = clientdata.ca_locality or ""
    local ca_state = clientdata.ca_state or ""
    local ca_country = clientdata.ca_country or "US"
    local ca_email = clientdata.ca_email or ""
    local ca_provisioner = clientdata.ca_provisioner or "admin"
    local ca_port = clientdata.ca_port or default_port
    local ca_validity_years = tonumber(clientdata.ca_validity_years) or 10
    local enable_ssh = clientdata.enable_ssh == "true"
    local gen_intermediate = clientdata.gen_intermediate == "true"
    local intermediate_validity_years = tonumber(clientdata.intermediate_validity_years) or 5

    -- Validate required fields
    if ca_common_name == "" then
        result.error = create_cfe("error", "CA Common Name is required!", "Error", "", "error")
        return result
    end

    -- Validate port
    if not ca_port:match("^%d+$") then
        result.error = create_cfe("error", "Invalid port number!", "Error", "", "error")
        return result
    end

    -- Validate hostname format
    local hostname_error = validate_hostname(ca_common_name, "CA Common Name")
    if hostname_error then
        result.error = create_cfe("error", hostname_error, "Error", "", "error")
        return result
    end

    -- Generate secure password using uuidgen or openssl
    local password_cmd = "uuidgen 2>/dev/null || openssl rand -hex 16"
    local password = exec_command(password_cmd):gsub("%s+", "")

    if password == "" then
        result.error = create_cfe("error", "Failed to generate password!", "Error", "", "error")
        return result
    end

    -- Create step-ca directories with correct ownership
    exec_command("mkdir -p " .. step_ca_base .. "/config " .. step_ca_base .. "/certs "
        .. step_ca_base .. "/secrets " .. step_ca_base .. "/db")

    -- Save password to file with secure permissions
    local pass_handle = io.open(step_password_file, "w")
    if not pass_handle then
        result.error = create_cfe("error", "Failed to create password file!", "Error", "", "error")
        return result
    end
    pass_handle:write(password)
    pass_handle:close()
    exec_command("chmod 600 " .. step_password_file)

    -- Set ownership to step-ca user
    local stepca_user = get_stepca_user()
    exec_command(string.format("chown -R %s:%s %s", stepca_user, stepca_user, step_ca_base))

    -- Initialize Root CA
    local init_cmd = string.format(
        "STEPPATH='%s' step ca init --name '%s' --dns '%s' --address ':%s'"
        .. " --provisioner '%s' --password-file '%s' --deployment-type standalone%s 2>&1",
        step_ca_base,
        ca_name,
        ca_common_name,
        ca_port,
        ca_provisioner,
        step_password_file,
        enable_ssh and " --ssh" or ""
    )

    local init_output = exec_as_stepca(init_cmd)

    -- Check if initialization succeeded
    if not mymodule.is_ca_initialized() then
        result.error = create_cfe(
            "error",
            "CA initialization failed! Output:\n" .. init_output,
            "Error",
            "",
            "error"
        )
        return result
    end

    -- Fix ownership after initialization
    exec_command(string.format("chown -R %s:%s %s", stepca_user, stepca_user, step_ca_base))

    -- Generate Intermediate CA if requested
    if gen_intermediate then
        local intermediate_cmd = string.format(
            "STEPPATH='%s' step certificate create '%s Intermediate CA'"
            .. " %s/certs/intermediate_ca.crt %s/secrets/intermediate_ca_key"
            .. " --profile intermediate-ca --ca %s/certs/root_ca.crt"
            .. " --ca-key %s/secrets/root_ca_key --ca-password-file %s"
            .. " --not-after=%dh --no-password --insecure 2>&1",
            step_ca_base,
            ca_name,
            step_ca_base,
            step_ca_base,
            step_ca_base,
            step_ca_base,
            step_password_file,
            intermediate_validity_years * 8760
        )
        exec_as_stepca(intermediate_cmd)
        exec_command(string.format("chmod 600 %s/secrets/intermediate_ca_key", step_ca_base))
    end

    -- Final ownership fix
    exec_command(string.format("chown -R %s:%s %s", stepca_user, stepca_user, step_ca_base))

    -- Success! Return password for user to save
    result.success = create_cfe(
        "success",
        "Certificate Authority initialized successfully!",
        "Success",
        "",
        "success"
    )

    result.ca_password = create_cfe(
        "ca_password",
        password,
        "CA Master Password",
        "CRITICAL: Save this password securely. It protects your CA private keys and cannot be recovered!",
        "password"
    )

    if enable_ssh then
        result.ssh_info = create_cfe(
            "ssh_info",
            "SSH CA keys generated: " .. step_ca_base .. "/certs/ssh_host_ca_key.pub and ssh_user_ca_key.pub",
            "SSH CA Initialized",
            "",
            "info"
        )
    end

    result.password_warning = create_cfe(
        "password_warning",
        "This password will only be shown ONCE. Store it in a secure password manager or encrypted vault. " ..
        "You can view it later in Step CA > Configuration > View CA Password (requires admin access).",
        "Important Warning",
        "",
        "warning"
    )

    return result
end

-- View CA password (admin-only)
function mymodule.get_ca_password()
    local result = {}

    -- Check if password file exists
    local pass_handle = io.open(step_password_file, "r")
    if not pass_handle then
        result.error = create_cfe(
            "error",
            "CA password file not found! This should not happen. Check " .. step_password_file .. " permissions.",
            "Error",
            "",
            "error"
        )
        return result
    end

    local password = pass_handle:read("*l")
    pass_handle:close()

    result.ca_password = create_cfe(
        "ca_password",
        password,
        "CA Master Password",
        "This password protects your CA private keys. Keep it secure!",
        "password"
    )

    result.warning = create_cfe(
        "warning",
        "Never share this password over unencrypted channels. " ..
        "Store it in a secure password manager. " ..
        "If lost, you cannot recover your CA private keys!",
        "Security Warning",
        "",
        "warning"
    )

    return result
end



-- Get client certificate form

function mymodule.get_client_form(clientdata)

    local form = {}



    form.client_name = create_cfe(

        clientdata.client_name or "",

        "Client Name",

        "Client identifier (e.g., netapp-cluster01, vsphere-vcenter, storage-array01)",

        "text"

    )



    form.client_type = create_cfe(

        clientdata.client_type or "generic",

        "Client Type",

        "Type of client",

        "select",

        {"generic", "netapp", "vmware-vsphere", "dell-emc", "pure-storage", "other"}

    )



    form.validity_days = create_cfe(

        clientdata.validity_days or "1095",

        "Validity (Days)",

        "Certificate validity period (default: 3 years)",

        "number"

    )



    form.description = create_cfe(

        clientdata.description or "",

        "Description",

        "Optional description or notes about this client",

        "text"

    )



    return form

end



-- Create Client certificate

function mymodule.create_client_certificate(clientdata)

    local result = {}



    local client_name = clientdata.client_name

    if not client_name or client_name == "" then

        result.error = create_cfe("Client name required", "Error", "", "error")

        return result

    end



    local client_type = clientdata.client_type or "generic"

    local validity = clientdata.validity_days or "1095"

    local cert_path = step_certs_path .. "/" .. client_name .. ".crt"

    local key_path = step_certs_path .. "/" .. client_name .. ".key"



    if file_exists(cert_path) then

        result.error = create_cfe("Certificate already exists for this client", "Error", "", "error")

        return result

    end



    local cmd = string.format(

        "step ca certificate '%s' '%s' '%s' --not-after=%sh --offline --no-password --insecure 2>&1",

        client_name, cert_path, key_path, validity

    )



    local output = exec_command(cmd)



    if file_exists(cert_path) then

        result.success = create_cfe("Client certificate created", "Success", "", "success")

        result.cert_pem = create_cfe(fs.read_file(cert_path), "Certificate (PEM)", "Install on client", "longtext")
        result.key_pem = create_cfe(fs.read_file(key_path), "Private Key (PEM)", "Keep secure", "longtext")



        if file_exists(step_certs_path .. "/root_ca.crt") then

            result.root_ca = create_cfe(

                fs.read_file(step_certs_path .. "/root_ca.crt"),

                "Root CA Certificate",

                "Install as trusted CA on client",

                "longtext"

            )

        end



        -- Client-type specific instructions
        local instructions
        if client_type == "netapp" then
            instructions = "NetApp ONTAP: See manual for 'security certificate install' steps."
        elseif client_type == "vmware-vsphere" then
            instructions = "VMware: Add as KMS cluster and upload CA/Client certs."
        else
            instructions = "Generic: Install Root CA and client certificate/key."
        end



        result.instructions = create_cfe(instructions, "Installation Instructions", "", "longtext")

    else

        result.error = create_cfe("Certificate creation failed: " .. output, "Error", "", "error")

    end



    return result

end



-- ===========================================================================
-- Duration Limit (Claims) Management
-- ===========================================================================

-- Get full provisioner details
function mymodule.get_provisioner_details(clientdata)
    local prov_name = clientdata.prov_name
    if not prov_name or prov_name == "" then
        return { error = create_cfe("error", "Provisioner name is required", "Error", "", "text") }
    end

    if not has_jq() then
        return { error = create_cfe("error", "The 'jq' utility is required.", "Error", "", "text") }
    end

    local filter = '.authority.provisioners[] | select(.name == "' .. prov_name .. '")'
    local full_json = exec_command("jq '" .. filter .. "' " .. step_config)

    if full_json == "" or full_json:lower():match("null") then
        return { error = create_cfe("error", "Provisioner '" .. prov_name .. "' not found.", "Error", "", "text") }
    end

    -- Extract specific parts for easier viewing
    local claims_json = exec_command("jq '" .. filter .. ".claims // {}' " .. step_config)
    local options_json = exec_command("jq '" .. filter .. ".options // {}' " .. step_config)

    return {
        prov_name = create_cfe("prov_name", prov_name, "Provisioner Name", "", "text"),
        full_json = create_cfe("full_json", full_json, "Full Configuration", "", "longtext"),
        claims_json = create_cfe("claims_json", claims_json, "Claims", "", "longtext"),
        options_json = create_cfe("options_json", options_json, "Options (Templates)", "", "longtext")
    }
end

-- Get token generation form
function mymodule.get_token_form(clientdata)
    local prov_name = clientdata.prov_name
    if not prov_name or prov_name == "" then
        return { error = create_cfe("error", "Provisioner name is required", "Error", "", "text") }
    end

    local form = {}
    form.prov_name = create_cfe("prov_name", prov_name, "Provisioner Name", "", "text")

    form.subject = create_cfe(
        "subject",
        clientdata.subject or "",
        "Certificate Subject",
        "The hostname or IP address the token will authorize (e.g., 'kanidm.local')",
        "text"
    )

    form.prov_password = create_cfe(
        "prov_password",
        "",
        "Provisioner Password",
        "The password generated when you created this JWK provisioner",
        "password"
    )

    return form
end

-- Generate a JWT token for a provisioner
function mymodule.generate_token(clientdata)
    local prov_name = clientdata.prov_name
    local subject = clientdata.subject
    local prov_pass = clientdata.prov_password

    if not prov_name or prov_name == "" or not subject or subject == "" or not prov_pass or prov_pass == "" then
        return {
            error = create_cfe("error", "All fields are required to generate a token", "Error", "", "text"),
            prov_name = create_cfe("prov_name", prov_name or "", "Provisioner", "", "text"),
            subject = create_cfe("subject", subject or "", "Subject", "", "text")
        }
    end

    local clean_prov_name = prov_name:gsub("^%s*(.-)%s*$", "%1")

    -- 1. Create a temporary password file for the provisioner password
    local tmp_pass = string.format("/tmp/token_pass_%d.txt", math.random(1000, 9999))
    local f_pass = io.open(tmp_pass, "w")
    if f_pass then
        f_pass:write(prov_pass)
        f_pass:close()
    end

    -- 2. Execute 'step ca token' using the password file
    -- Syntax: step ca token --issuer=NAME --password-file=FILE SUBJECT
    local cmd = string.format(
        "step ca token --issuer='%s' --password-file='%s' --ca-config='%s' '%s' 2>&1",
        clean_prov_name, tmp_pass, step_config, subject
    )

    local output = exec_as_stepca(cmd)

    -- Cleanup the temp password file
    os.remove(tmp_pass)

    -- Clean ANSI and find the token (JWT starts with ey and has dots)
    local clean_output = output:gsub("%[%d+;%d+;%d+m", ""):gsub("%[%d+;%d+m", ""):gsub("%[%d+m", ""):gsub("%[0m", "")
    local token = clean_output:match("(eyJ[%w%-_%.]+)")

    if token then
        return {
            success = create_cfe("success", "Token generated successfully for " .. subject, "Success", "", "text"),
            token = create_cfe(
                "token", token, "Token (JWT)",
                "Use with: 'step ca certificate --token <token>'", "longtext"
            ),
            subject = create_cfe("subject", subject, "Subject", "", "text"),
            prov_name = create_cfe("prov_name", prov_name, "Provisioner", "", "text")
        }
    else
        return {
            error = create_cfe("error", "Failed to generate token: " .. clean_output, "Error", "", "text"),
            prov_name = create_cfe("prov_name", prov_name, "Provisioner", "", "text"),
            subject = create_cfe("subject", subject, "Subject", "", "text")
        }
    end
end

-- Get global CA claims from ca.json
function mymodule.get_global_claims()
    local config_content = fs.read_file(step_config)
    local claims = {}

    -- Basic extraction of global claims
    -- Using jq if available is much safer for reading too
    if has_jq() then
        claims.min_dur = exec_command(
            "jq -r '.authority.claims.minTLSCertDuration // \"\"' " .. step_config):gsub("%s+", "")
        claims.max_dur = exec_command(
            "jq -r '.authority.claims.maxTLSCertDuration // \"\"' " .. step_config):gsub("%s+", "")
        claims.default_dur = exec_command(
            "jq -r '.authority.claims.defaultTLSCertDuration // \"\"' " .. step_config):gsub("%s+", "")
    else
        -- Fallback to basic string matching
        claims.min_dur = config_content:match('"minTLSCertDuration"%s*:%s*"([^"]+)"') or ""
        claims.max_dur = config_content:match('"maxTLSCertDuration"%s*:%s*"([^"]+)"') or ""
        claims.default_dur = config_content:match('"defaultTLSCertDuration"%s*:%s*"([^"]+)"') or ""
    end

    return {
        min_dur = create_cfe("min_dur", claims.min_dur, "Global Min", "e.g., 5m, 1h", "text"),
        max_dur = create_cfe("max_dur", claims.max_dur, "Global Max", "e.g., 24h, 365d", "text"),
        default_dur = create_cfe("default_dur", claims.default_dur, "Global Default", "e.g., 24h", "text"),
        has_jq = create_cfe("has_jq", tostring(has_jq()), "JQ Available", "", "boolean")
    }
end

-- Save global CA claims using jq
function mymodule.save_global_claims(clientdata)
    local result = mymodule.get_global_claims()

    if not has_jq() then
        result.error = create_cfe("error", "Advanced config requires 'jq'. Install: apk add jq", "Error", "", "text")
        return result
    end

    -- Validate formats
    local err = validate_duration(clientdata.min_dur, "Global Min Duration") or
                validate_duration(clientdata.max_dur, "Global Max Duration") or
                validate_duration(clientdata.default_dur, "Global Default Duration")

    if err then
        result.error = create_cfe("error", err, "Validation Error", "", "text")
        return result
    end

    local min = normalize_duration(clientdata.min_dur)
    local max = normalize_duration(clientdata.max_dur)
    local def = normalize_duration(clientdata.default_dur)

    -- Build jq filter dynamically to skip empty values
    local updates = {}
    if min then table.insert(updates, string.format('.authority.claims.minTLSCertDuration = "%s"', min)) end
    if max then table.insert(updates, string.format('.authority.claims.maxTLSCertDuration = "%s"', max)) end
    if def then table.insert(updates, string.format('.authority.claims.defaultTLSCertDuration = "%s"', def)) end

    if #updates == 0 then
        result.success = create_cfe("success", "No changes were made.", "Success", "", "text")
        return result
    end

    local filter = table.concat(updates, " | ")

    local tmp_file = "/tmp/ca.json.tmp"
    local cmd = string.format(
        "jq '%s' %s > %s && mv %s %s 2>/dev/null", filter, step_config, tmp_file, tmp_file, step_config)

    local output = exec_as_stepca(cmd)

    -- Check service status for context-specific feedback
    local step_status = exec_command("rc-service " .. servicename .. " status 2>&1")
    local is_running = step_status:match("started")

    local success_msg = "Global claims updated."
    if is_running then
        success_msg = success_msg .. " Restart or reload step-ca service to apply changes."
    else
        success_msg = success_msg .. " The service is currently stopped; changes will take effect when it starts."
    end

    result.success = create_cfe("success", success_msg, "Success", "", "text")
    result.is_running = is_running
    result.restart_required = true

    -- Update result values
    result.min_dur.value = clientdata.min_dur
    result.max_dur.value = clientdata.max_dur
    result.default_dur.value = clientdata.default_dur

    return result
end

-- Get provisioner-specific claims
function mymodule.get_provisioner_claims(clientdata)
    local prov_name = clientdata.prov_name
    if not prov_name then return { error = "Provisioner name missing" } end

    local claims = {}
    if has_jq() then
        local base_filter = '.authority.provisioners[] | select(.name == "' .. prov_name .. '") | .claims'
        claims.x509_min = exec_command(
            "jq -r '" .. base_filter .. ".minTLSCertDuration // \"\"' " .. step_config):gsub("%s+", "")
        claims.x509_max = exec_command(
            "jq -r '" .. base_filter .. ".maxTLSCertDuration // \"\"' " .. step_config):gsub("%s+", "")
        claims.x509_def = exec_command(
            "jq -r '" .. base_filter .. ".defaultTLSCertDuration // \"\"' " .. step_config):gsub("%s+", "")
    end

    return {
        prov_name = create_cfe("prov_name", prov_name, "Provisioner", "", "text"),
        x509_min = create_cfe("x509_min", claims.x509_min, "X.509 Min Duration", "e.g., 1h, 1d", "text"),
        x509_max = create_cfe("x509_max", claims.x509_max, "X.509 Max Duration", "e.g., 30d, 365d", "text"),
        x509_def = create_cfe("x509_def", claims.x509_def, "X.509 Default Duration", "e.g., 24h", "text"),
        has_jq = create_cfe("has_jq", tostring(has_jq()), "JQ Available", "", "boolean")
    }
end

-- Save provisioner-specific claims using jq
function mymodule.save_provisioner_claims(clientdata)
    local result = mymodule.get_provisioner_claims(clientdata)

    if not has_jq() then
        result.error = create_cfe("error", "Advanced configuration requires 'jq' package.", "Error", "", "text")
        return result
    end

    local name = clientdata.prov_name
    if not name or name == "" then
        result.error = create_cfe("error", "Provisioner name is missing.", "Error", "", "text")
        return result
    end

    -- Validate formats
    local err = validate_duration(clientdata.x509_min, "X.509 Min Duration") or
                validate_duration(clientdata.x509_max, "X.509 Max Duration") or
                validate_duration(clientdata.x509_def, "X.509 Default Duration")

    if err then
        result.error = create_cfe("error", err, "Validation Error", "", "text")
        return result
    end

    local min = normalize_duration(clientdata.x509_min)
    local max = normalize_duration(clientdata.x509_max)
    local def = normalize_duration(clientdata.x509_def)

    -- Build partial JSON object for claims dynamically
    local claims_parts = {}
    if min then table.insert(claims_parts, string.format('minTLSCertDuration: "%s"', min)) end
    if max then table.insert(claims_parts, string.format('maxTLSCertDuration: "%s"', max)) end
    if def then table.insert(claims_parts, string.format('defaultTLSCertDuration: "%s"', def)) end

    if #claims_parts == 0 then
        result.success = create_cfe("success", "No changes were made.", "Success", "", "text")
        return result
    end

    local claims_json = "{" .. table.concat(claims_parts, ", ") .. "}"

    -- jq filter to find provisioner by name and update its claims
    -- This adds the claims object if it doesn't exist
    local filter = string.format(
        '(.authority.provisioners[] | select(.name == "%s") | .claims) |= (. + %s)',
        name, claims_json
    )

    local tmp_file = "/tmp/ca.json.tmp"
    -- Redirect stderr to /dev/null or capture it to avoid pollutive output
    local cmd = string.format(
        "jq '%s' %s > %s && mv %s %s 2>/dev/null", filter, step_config, tmp_file, tmp_file, step_config)

    local output = exec_as_stepca(cmd)

    -- Check service status for context-specific feedback
    local step_status = exec_command("rc-service " .. servicename .. " status 2>&1")
    local is_running = step_status:match("started")

    local success_msg = string.format("Provisioner claims updated for '%s'.", name)
    if is_running then
        success_msg = success_msg .. " Restart or reload step-ca service to apply changes."
    else
        success_msg = success_msg .. " The service is currently stopped; changes will take effect when it starts."
    end

    -- Check if file was actually updated (output might contain su noise)
    result.success = create_cfe("success", success_msg, "Success", "", "text")
    result.is_running = is_running
    result.restart_required = true

    -- Update the result values with what was just saved
    result.x509_min.value = clientdata.x509_min
    result.x509_max.value = clientdata.x509_max
    result.x509_def.value = clientdata.x509_def

    return result
end

-- ===========================================================================
-- SSH Certificate Signing
-- ===========================================================================

-- Get SSH certificate signing form
function mymodule.get_ssh_sign_form(clientdata)
    clientdata = clientdata or {}
    local form = {}

    local has_ssh = file_exists(step_ca_base .. "/certs/ssh_user_ca_key.pub")
    form.has_ssh = create_cfe(
        "has_ssh", tostring(has_ssh), "SSH CA Available",
        "Whether the CA was initialized with SSH support (required for SSH certificate signing)", "text"
    )

    form.ssh_pub_key = create_cfe(
        "ssh_pub_key", clientdata.ssh_pub_key or "",
        "SSH Public Key",
        "Paste the contents of the user's ~/.ssh/id_ed25519.pub, id_rsa.pub, etc.",
        "longtext"
    )

    form.identity = create_cfe(
        "identity", clientdata.identity or "",
        "Certificate Identity",
        "Identity stored in the certificate (e.g. alice@company.com or alice@hostname)",
        "text"
    )

    form.principals = create_cfe(
        "principals", clientdata.principals or "",
        "Principals (Unix usernames)",
        "Comma-separated list of usernames this certificate authorizes (e.g. alice,root)",
        "text"
    )

    form.validity = create_cfe(
        "validity", clientdata.validity or "24h",
        "Validity",
        "How long the certificate is valid — use s, m, h, or d (e.g. 24h, 7d, 365d)",
        "text"
    )

    form.cert_type = create_cfe(
        "cert_type", clientdata.cert_type or "user",
        "Certificate Type",
        "User certificates authenticate users to SSH servers. Host certificates authenticate servers to users.",
        "select", {"user", "host"}
    )

    return form
end

-- Sign an SSH public key using the step-ca SSH user or host CA key
function mymodule.sign_ssh_cert(clientdata)
    local result = {}
    clientdata = clientdata or {}

    -- Guard: SSH CA must be initialized
    if not file_exists(step_ca_base .. "/certs/ssh_user_ca_key.pub") then
        result.error = create_cfe(
            "error",
            "SSH CA not initialized. Re-initialize the CA with 'Enable SSH Certificate Authority' checked.",
            "Error", "", "text"
        )
        return result
    end

    -- Clean and validate inputs
    local ssh_pub_key = (clientdata.ssh_pub_key or ""):gsub("^%s*(.-)%s*$", "%1")
    local identity    = (clientdata.identity    or ""):gsub("^%s*(.-)%s*$", "%1")
    local principals  = (clientdata.principals  or ""):gsub("^%s*(.-)%s*$", "%1")
    local validity    = (clientdata.validity    or "24h"):gsub("^%s*(.-)%s*$", "%1")
    local cert_type   = clientdata.cert_type or "user"

    if ssh_pub_key == "" then
        result.error = create_cfe("error", "SSH public key is required", "Error", "", "text")
        return result
    end
    if identity == "" then
        result.error = create_cfe("error", "Certificate identity is required", "Error", "", "text")
        return result
    end
    if principals == "" then
        result.error = create_cfe("error", "At least one principal is required", "Error", "", "text")
        return result
    end

    -- Basic key format check
    if not ssh_pub_key:match("^ssh%-") and not ssh_pub_key:match("^ecdsa%-sha2") then
        result.error = create_cfe(
            "error",
            "Invalid SSH public key. Must start with ssh-ed25519, ssh-rsa, ecdsa-sha2-nistp256, etc.",
            "Error", "", "text"
        )
        return result
    end

    -- Validate and normalize validity duration
    local validity_norm = normalize_duration(validity)
    if not validity_norm then
        result.error = create_cfe(
            "error",
            "Invalid validity format. Use a number followed by s, m, h, or d (e.g. 24h, 7d).",
            "Error", "", "text"
        )
        return result
    end

    -- Write public key to a temp file
    local tmp_dir = exec_command("mktemp -d /tmp/step-ssh-XXXXXX 2>/dev/null"):gsub("%s+", "")
    if tmp_dir == "" then
        result.error = create_cfe("error", "Failed to create temporary directory", "Error", "", "text")
        return result
    end

    local tmp_pub  = tmp_dir .. "/key.pub"
    local tmp_cert = tmp_dir .. "/key-cert.pub"

    local fh = io.open(tmp_pub, "w")
    if not fh then
        exec_command("rm -rf '" .. tmp_dir .. "'")
        result.error = create_cfe("error", "Failed to write temporary key file", "Error", "", "text")
        return result
    end
    fh:write(ssh_pub_key .. "\n")
    fh:close()

    -- Build --principal flags (one per principal)
    local principal_flags = {}
    for p in principals:gmatch("[^,]+") do
        local trimmed = p:match("^%s*(.-)%s*$")
        if trimmed ~= "" then
            table.insert(principal_flags, string.format("--principal '%s'", trimmed:gsub("'", "'\\''")))
        end
    end

    local host_flag = (cert_type == "host") and " --host" or ""

    local sign_cmd = string.format(
        "STEPPATH='%s' step ssh certificate"
        .. " --offline"
        .. " --password-file '%s'"
        .. " --not-after '%s'"
        .. " %s%s"
        .. " '%s' '%s' 2>&1",
        step_ca_base,
        step_password_file,
        validity_norm,
        table.concat(principal_flags, " "),
        host_flag,
        identity:gsub("'", "'\\''"),
        tmp_pub
    )

    local output = exec_as_stepca(sign_cmd)

    -- Read the signed certificate
    local cert_content = ""
    local cf = io.open(tmp_cert, "r")
    if cf then
        cert_content = cf:read("*a")
        cf:close()
    end

    exec_command("rm -rf '" .. tmp_dir .. "'")

    if cert_content ~= "" then
        local safe_id = identity:gsub("[^a-zA-Z0-9._@-]", "_")
        result.success     = create_cfe("success",      "SSH certificate signed successfully.", "Success", "", "text")
        result.cert_content= create_cfe("cert_content", cert_content:gsub("%s+$", ""),
            "Signed SSH Certificate",
            "Save this as ~/.ssh/" .. safe_id .. "-cert.pub on the user's machine",
            "longtext")
        result.filename    = create_cfe("filename",     safe_id .. "-cert.pub",  "Filename",   "", "text")
        result.identity    = create_cfe("identity",     identity,                "Identity",   "", "text")
        result.principals  = create_cfe("principals",   principals,              "Principals", "", "text")
        result.validity    = create_cfe("validity",     validity_norm,           "Validity",   "", "text")
        result.cert_type   = create_cfe("cert_type",    cert_type,               "Type",       "", "text")
    else
        local clean = output:gsub("\27%[[%d;]*m", ""):gsub("^%s+", ""):gsub("%s+$", "")
        result.error = create_cfe("error", "SSH certificate signing failed:\n" .. clean, "Error", "", "text")
        result.debug = create_cfe("debug", output, "Debug Output", "", "longtext")
    end

    return result
end

return mymodule
