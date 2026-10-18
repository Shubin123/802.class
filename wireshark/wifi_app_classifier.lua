-- Wi-Fi Application Classifier — Wireshark Extension
--
-- Provides:
--  1. Native Postdissector for Raw 802.11 Monitor Frames (wlan.fc.type == 2)
--  2. Display Filters:
--       wifi_app
--       wifi_app.bssid
--       wifi_app.client
--       wifi_app.direction == "uplink" | "downlink"
--       wifi_app.protected == true
--       wifi_app.prediction == "<app_label>" | "unknown"
--       wifi_app.confidence >= 0.70
--       wifi_app.session_id
--       wifi_app.qos_tid
--  3. Wireshark GUI Menu Tools:
--       - Tools -> Wi-Fi App Classifier -> 🎯 Classify Current Capture File
--       - Tools -> Wi-Fi App Classifier -> 📡 Discover BSSIDs & Channels
--       - Tools -> Wi-Fi App Classifier -> 🔍 Audit Selected Packet / Session
--       - Tools -> Wi-Fi App Classifier -> ⚡ Classifier Status & Benchmarks

local wifi_app = Proto("wifi_app", "802.11 Raw Application Classifier")

-- Protocol Fields
local f_active     = ProtoField.bool("wifi_app.active", "Classifier Scoped")
local f_bssid      = ProtoField.string("wifi_app.bssid", "Target BSSID")
local f_client     = ProtoField.string("wifi_app.client", "Client MAC")
local f_dir        = ProtoField.string("wifi_app.direction", "Frame Direction")
local f_protected  = ProtoField.bool("wifi_app.protected", "Protected Data Frame")
local f_tid        = ProtoField.uint8("wifi_app.qos_tid", "QoS TID", base.DEC)
local f_mpdu_len   = ProtoField.uint32("wifi_app.mpdu_len", "MPDU Length (bytes)", base.DEC)
local f_pay_len    = ProtoField.uint32("wifi_app.payload_len", "Payload Length (bytes)", base.DEC)
local f_seq        = ProtoField.uint16("wifi_app.sequence_number", "Sequence Number", base.DEC)
local f_retry      = ProtoField.bool("wifi_app.is_retry", "Retry Flag")
local f_iat_ms     = ProtoField.float("wifi_app.iat_ms", "Inter-Arrival Time (ms)")
local f_pred       = ProtoField.string("wifi_app.prediction", "Predicted Application")
local f_conf       = ProtoField.float("wifi_app.confidence", "Model Confidence")
local f_model      = ProtoField.string("wifi_app.model", "Model Engine")
local f_session    = ProtoField.string("wifi_app.session_id", "Session Track ID")
local f_window     = ProtoField.uint32("wifi_app.window_index", "Window Index", base.DEC)

wifi_app.fields = {
    f_active, f_bssid, f_client, f_dir, f_protected,
    f_tid, f_mpdu_len, f_pay_len, f_seq, f_retry, f_iat_ms,
    f_pred, f_conf, f_model, f_session, f_window
}

-- WLAN Field Extractors
local wlan_type_f     = Field.new("wlan.fc.type")
local wlan_subtype_f  = Field.new("wlan.fc.subtype")
local wlan_tods_f     = Field.new("wlan.fc.tods")
local wlan_fromds_f   = Field.new("wlan.fc.fromds")
local wlan_prot_f     = Field.new("wlan.fc.protected")
local wlan_retry_f    = Field.new("wlan.fc.retry")
local wlan_ra_f       = Field.new("wlan.ra")
local wlan_ta_f       = Field.new("wlan.ta")
local wlan_bssid_f    = Field.new("wlan.bssid")
local wlan_tid_f      = Field.new("wlan.qos.tid")
local wlan_seq_f      = Field.new("wlan.seq")
local wlan_duration_f = Field.new("wlan.duration")
local frame_time_f    = Field.new("frame.time_epoch")
local frame_len_f     = Field.new("frame.len")
local rt_signal_f     = Field.new("radiotap.dbm_antsignal")
local rt_rate_f       = Field.new("radiotap.datarate")
local rt_mcs_f        = Field.new("radiotap.mcs.index")

-- Resolve repository paths
local function script_dir()
    local str = debug.getinfo(1, "S").source:sub(2)
    return str:match("(.*/)") or "./"
end

local ROOT = os.getenv("WIFI_APP_ROOT") or "/Users/kafka/Documents/802.class"
local HELPER_PATH = ROOT .. "/wireshark/wifi_app_helper.py"
local CACHE_PATH = "/tmp/wifi_app_sessions.json"
local WEIGHTS_PATH = ROOT .. "/models/active_model.json"

--------------------------------------------------------------------------------
-- Lightweight JSON Parser
--------------------------------------------------------------------------------
local json = {}
function json.parse(str)
    if not str or str == "" then return nil end
    local index = 1
    local len = #str

    local function skip_whitespace()
        while index <= len and str:sub(index, index):match("%s") do index = index + 1 end
    end

    local parse_value

    local function parse_string()
        index = index + 1
        local s = ""
        while index <= len do
            local c = str:sub(index, index)
            if c == '"' then
                index = index + 1
                return s
            elseif c == '\\' then
                index = index + 1
                local esc = str:sub(index, index)
                if esc == 'n' then s = s .. '\n'
                elseif esc == 't' then s = s .. '\t'
                elseif esc == 'r' then s = s .. '\r'
                elseif esc == '"' then s = s .. '"'
                elseif esc == '\\' then s = s .. '\\'
                else s = s .. esc end
                index = index + 1
            else
                s = s .. c
                index = index + 1
            end
        end
        return s
    end

    local function parse_number()
        local s = index
        while index <= len and str:sub(index, index):match("[%d%.%-%+eE]") do index = index + 1 end
        return tonumber(str:sub(s, index - 1))
    end

    local function parse_array()
        index = index + 1
        local arr = {}
        skip_whitespace()
        if index <= len and str:sub(index, index) == ']' then
            index = index + 1
            return arr
        end
        while index <= len do
            local val = parse_value()
            table.insert(arr, val)
            skip_whitespace()
            local c = str:sub(index, index)
            if c == ']' then
                index = index + 1
                return arr
            elseif c == ',' then
                index = index + 1
                skip_whitespace()
            else
                break
            end
        end
        return arr
    end

    local function parse_object()
        index = index + 1
        local obj = {}
        skip_whitespace()
        if index <= len and str:sub(index, index) == '}' then
            index = index + 1
            return obj
        end
        while index <= len do
            skip_whitespace()
            if str:sub(index, index) ~= '"' then break end
            local key = parse_string()
            skip_whitespace()
            if str:sub(index, index) == ':' then index = index + 1 end
            skip_whitespace()
            local val = parse_value()
            obj[key] = val
            skip_whitespace()
            local c = str:sub(index, index)
            if c == '}' then
                index = index + 1
                return obj
            elseif c == ',' then
                index = index + 1
                skip_whitespace()
            else
                break
            end
        end
        return obj
    end

    parse_value = function()
        skip_whitespace()
        if index > len then return nil end
        local c = str:sub(index, index)
        if c == '"' then return parse_string()
        elseif c == '{' then return parse_object()
        elseif c == '[' then return parse_array()
        elseif c:match("[%d%-%+]") then return parse_number()
        elseif str:sub(index, index + 3) == "true" then index = index + 4; return true
        elseif str:sub(index, index + 4) == "false" then index = index + 5; return false
        elseif str:sub(index, index + 3) == "null" then index = index + 4; return nil
        else
            index = index + 1
            return nil
        end
    end

    local ok, res = pcall(parse_value)
    return ok and res or nil
end

--------------------------------------------------------------------------------
-- Session Cache & Model Loading
--------------------------------------------------------------------------------
local session_cache = nil
local last_cache_mtime = 0

local function load_session_cache()
    local f = io.open(CACHE_PATH, "r")
    if not f then return nil end
    local content = f:read("*a")
    f:close()
    session_cache = json.parse(content)
    return session_cache
end

-- Active model weights for real-time classification
local active_model = nil
local function load_model_weights()
    local f = io.open(WEIGHTS_PATH, "r")
    if not f then return nil end
    local content = f:read("*a")
    f:close()
    active_model = json.parse(content)
    return active_model
end

-- Load available assets on startup
load_session_cache()
load_model_weights()

--------------------------------------------------------------------------------
-- Real-time Streaming Client Window State
--------------------------------------------------------------------------------
-- Tracks frames per client MAC to evaluate sliding windows in pure Lua
local client_tracks = {}

local function update_client_track(client_mac, bssid, obs)
    local track = client_tracks[client_mac]
    if not track then
        track = {
            client_mac = client_mac,
            bssid = bssid,
            frames = {},
            last_timestamp = obs.timestamp,
            last_seq = {},
            session_ordinal = 1,
        }
        client_tracks[client_mac] = track
    end

    -- Idle gap check (15 seconds)
    if obs.timestamp - track.last_timestamp > 15.0 then
        track.session_ordinal = track.session_ordinal + 1
        track.frames = {}
    end
    track.last_timestamp = obs.timestamp

    -- Compute IAT
    local iat_ms = math.min((obs.timestamp - (track.prev_time or obs.timestamp)) * 1000.0, 60000.0)
    track.prev_time = obs.timestamp

    -- Compute Seq Delta
    local prev_seq = track.last_seq[obs.direction]
    local seq_delta = 0
    if prev_seq and obs.seq then
        seq_delta = (obs.seq - prev_seq) % 4096
    end
    if obs.seq then track.last_seq[obs.direction] = obs.seq end

    -- Vector of 18 features matching FEATURE_COLUMNS contract:
    -- 1: direction (+1 uplink, -1 downlink)
    -- 2: mpdu_len
    -- 3: payload_len
    -- 4: iat_ms
    -- 5: log_iat
    -- 6: is_retry
    -- 7: seq_delta
    -- 8: qos_tid
    -- 9: has_qos
    -- 10: is_protected
    -- 11: subtype
    -- 12: duration
    -- 13: signal_dbm
    -- 14: signal_missing
    -- 15: data_rate
    -- 16: rate_missing
    -- 17: mcs_index
    -- 18: mcs_missing
    local frame_features = {
        obs.direction == "uplink" and 1.0 or -1.0,
        obs.mpdu_len,
        obs.payload_len,
        iat_ms,
        math.log(1.0 + iat_ms),
        obs.retry and 1.0 or 0.0,
        seq_delta,
        obs.qos_tid or 0.0,
        obs.qos_tid and 1.0 or 0.0,
        obs.protected and 1.0 or 0.0,
        obs.subtype,
        obs.duration,
        obs.signal_dbm or 0.0,
        obs.signal_dbm and 0.0 or 1.0,
        obs.data_rate or 0.0,
        obs.data_rate and 0.0 or 1.0,
        obs.mcs_index or 0.0,
        obs.mcs_index and 0.0 or 1.0,
    }

    table.insert(track.frames, frame_features)
    if #track.frames > 64 then
        table.remove(track.frames, 1)
    end

    return track
end

-- Evaluate aggregate baseline weights (72 features: mean, std, min, max of 18 channels)
local function evaluate_track_baseline(track)
    if not active_model or not active_model.coefficients then return nil, nil end
    local n = #track.frames
    if n < 4 then return "insufficient_data", 0.0 end

    -- Compute mean, std, min, max across frames for each of the 18 channels
    local agg = {}
    local sums = {}
    local mins = {}
    local maxs = {}
    for c = 1, 18 do
        sums[c] = 0.0
        mins[c] = track.frames[1][c]
        maxs[c] = track.frames[1][c]
    end

    for i = 1, n do
        local f = track.frames[i]
        for c = 1, 18 do
            local val = f[c]
            sums[c] = sums[c] + val
            if val < mins[c] then mins[c] = val end
            if val > maxs[c] then maxs[c] = val end
        end
    end

    -- 1..18: means
    for c = 1, 18 do table.insert(agg, sums[c] / n) end
    -- 19..36: stds
    for c = 1, 18 do
        local mean = sums[c] / n
        local sq_sum = 0.0
        for i = 1, n do
            local diff = track.frames[i][c] - mean
            sq_sum = sq_sum + (diff * diff)
        end
        table.insert(agg, math.sqrt(sq_sum / n))
    end
    -- 37..54: mins
    for c = 1, 18 do table.insert(agg, mins[c]) end
    -- 55..72: maxs
    for c = 1, 18 do table.insert(agg, maxs[c]) end

    -- Logistic inference
    local coefs = active_model.coefficients
    local intercepts = active_model.intercepts
    local labels = active_model.labels

    if active_model.is_binary then
        local logit = intercepts[1] or 0.0
        local w = coefs[1]
        for j = 1, 72 do logit = logit + (w[j] or 0.0) * (agg[j] or 0.0) end
        local p1 = 1.0 / (1.0 + math.exp(-logit))
        local p0 = 1.0 - p1
        if p1 >= p0 then
            return labels[2] or "class_1", p1
        else
            return labels[1] or "class_0", p0
        end
    else
        local num_classes = #labels
        local max_logit = -1e9
        local logits = {}
        for c = 1, num_classes do
            local l = intercepts[c] or 0.0
            local w = coefs[c] or {}
            for j = 1, 72 do l = l + (w[j] or 0.0) * (agg[j] or 0.0) end
            logits[c] = l
            if l > max_logit then max_logit = l end
        end
        local sum_exp = 0.0
        local probs = {}
        for c = 1, num_classes do
            local e = math.exp(logits[c] - max_logit)
            probs[c] = e
            sum_exp = sum_exp + e
        end
        local best_c = 1
        local best_p = 0.0
        for c = 1, num_classes do
            local p = probs[c] / sum_exp
            if p > best_p then
                best_p = p
                best_c = c
            end
        end
        return labels[best_c] or "unknown", best_p
    end
end

--------------------------------------------------------------------------------
-- Main Postdissector
--------------------------------------------------------------------------------
function wifi_app.dissector(tvb, pinfo, tree)
    local type_f = wlan_type_f()
    if not type_f or tonumber(type_f.value) ~= 2 then
        return
    end

    local subtype_f = wlan_subtype_f()
    local subtype = subtype_f and tonumber(subtype_f.value) or 0
    -- Accept data-bearing subtypes (0, 8, etc.)
    if subtype == 4 or subtype == 12 then
        return -- Null or QoS-Null
    end

    local tods = wlan_tods_f() and wlan_tods_f().value or false
    local fromds = wlan_fromds_f() and wlan_fromds_f().value or false
    if (tods and fromds) or (not tods and not fromds) then
        return
    end

    local ra = wlan_ra_f() and tostring(wlan_ra_f().value):lower() or ""
    local ta = wlan_ta_f() and tostring(wlan_ta_f().value):lower() or ""
    local bssid_f = wlan_bssid_f()
    local bssid = bssid_f and tostring(bssid_f.value):lower() or ""

    local direction = "unknown"
    local client_mac = "unknown"
    if tods and not fromds then
        direction = "uplink"
        client_mac = ta
        if bssid == "" then bssid = ra end
    else
        direction = "downlink"
        client_mac = ra
        if bssid == "" then bssid = ta end
    end

    local is_prot = wlan_prot_f() and wlan_prot_f().value or false
    local is_retry = wlan_retry_f() and wlan_retry_f().value or false
    local tid = wlan_tid_f() and tonumber(wlan_tid_f().value) or nil
    local seq = wlan_seq_f() and tonumber(wlan_seq_f().value) or nil
    local duration = wlan_duration_f() and tonumber(wlan_duration_f().value) or 0
    local mpdu_len = frame_len_f() and tonumber(frame_len_f().value) or tvb:len()
    local payload_len = math.max(0, mpdu_len - (tid and 36 or 34))

    local pkt_time = frame_time_f() and tonumber(frame_time_f().value) or (pinfo.abs_ts or 0.0)

    -- 1. Check offline batch cache first
    local prediction = nil
    local confidence = nil
    local session_id = nil
    local model_used = "none"
    local window_idx = 0

    if session_cache and session_cache.windows then
        for i, w in ipairs(session_cache.windows) do
            if w.client_mac == client_mac and pkt_time >= (w.start_time - 0.01) and pkt_time <= (w.end_time + 0.01) then
                prediction = w.prediction
                confidence = w.confidence
                session_id = w.session_id
                model_used = session_cache.model_kind or "tcn"
                window_idx = i
                break
            end
        end
    end

    -- 2. Fallback to real-time streaming sliding window
    if not prediction then
        local obs = {
            timestamp = pkt_time,
            direction = direction,
            mpdu_len = mpdu_len,
            payload_len = payload_len,
            retry = is_retry,
            seq = seq,
            qos_tid = tid,
            protected = is_prot,
            subtype = subtype,
            duration = duration,
            signal_dbm = rt_signal_f() and tonumber(rt_signal_f().value) or nil,
            data_rate = rt_rate_f() and tonumber(rt_rate_f().value) or nil,
            mcs_index = rt_mcs_f() and tonumber(rt_mcs_f().value) or nil,
        }
        local track = update_client_track(client_mac, bssid, obs)
        prediction, confidence = evaluate_track_baseline(track)
        session_id = string.format("%s:%03d", client_mac, track.session_ordinal)
        model_used = "realtime_baseline"
    end

    -- Populate Wireshark Tree
    local subtree = tree:add(wifi_app, tvb(), "Raw 802.11 Application Classifier")
    subtree:add(f_active, true)
    subtree:add(f_bssid, bssid)
    subtree:add(f_client, client_mac)
    subtree:add(f_dir, direction)
    subtree:add(f_protected, is_prot)
    subtree:add(f_mpdu_len, mpdu_len)
    subtree:add(f_pay_len, payload_len)
    if seq then subtree:add(f_seq, seq) end
    subtree:add(f_retry, is_retry)
    if tid then subtree:add(f_tid, tid) end

    if prediction then
        subtree:add(f_pred, prediction)
        subtree:add(f_conf, confidence or 0.0)
        subtree:add(f_model, model_used)
        if session_id then subtree:add(f_session, session_id) end
        if window_idx > 0 then subtree:add(f_window, window_idx) end

        -- Append prediction to Info column for quick visual inspection
        local conf_str = confidence and string.format(" (%d%%)", math.floor(confidence * 100)) or ""
        pinfo.cols.info:append(string.format(" [App: %s%s]", prediction, conf_str))
    end
end

register_postdissector(wifi_app)

--------------------------------------------------------------------------------
-- Wireshark GUI Menu Tools
--------------------------------------------------------------------------------

local function run_helper_cmd(args_str)
    local cmd = string.format('python3 "%s" %s 2>&1', HELPER_PATH, args_str)
    local pipe = io.popen(cmd)
    local result = pipe and pipe:read("*a") or "Failed to execute helper"
    if pipe then pipe:close() end
    return result
end

-- 1. Classify Open Capture
local function menu_classify_capture()
    local win = TextWindow.new("Wi-Fi App Classifier: Capture Analysis")
    win:set_editable(false)
    win:append("Analyzing capture with BSSID-scoped model pipeline...\n")
    win:append("Scanning client observation windows and evaluating application features...\n\n")

    -- Check if capture path was cached or look for standard field capture
    local pcap_to_run = nil
    if session_cache and session_cache.pcap and file_exists and file_exists(session_cache.pcap) then
        pcap_to_run = session_cache.pcap
    else
        -- Search standard directories for recent capture
        local candidates = {
            ROOT .. "/data/field/cm4/cm4-wpa2-d85af33381ea-000.pcapng",
            ROOT .. "/data/field/diagnostics/disassociated.pcapng",
            ROOT .. "/data/field/cm4/capture.pcapng",
            ROOT .. "/data/field/install-check/synthetic-16-fixture_small-0.pcap",
            ROOT .. "/data/real/sessions/session_001.pcapng",
        }
        for _, c in ipairs(candidates) do
            local f = io.open(c, "r")
            if f then f:close(); pcap_to_run = c; break end
        end
    end

    if not pcap_to_run then
        win:set("No active capture found.\nTo classify a capture, provide a PCAP file in data/field/ or data/real/.")
        return
    end

    local output = run_helper_cmd(string.format('--classify-capture "%s"', pcap_to_run))
    load_session_cache()
    win:set(output)
end

-- 2. Discover BSSIDs & Channels
local function menu_discover_bssids()
    local win = TextWindow.new("Wi-Fi App Classifier: BSSID & Channel Discovery")
    win:set_editable(false)
    win:append("Scanning beacons for radio BSSIDs, SSIDs, and operating channels...\n\n")

    local pcap_to_run = session_cache and session_cache.pcap or (ROOT .. "/data/field/install-check/synthetic-16-fixture_small-0.pcap")
    local output = run_helper_cmd(string.format('--discover-bssids "%s"', pcap_to_run))
    win:set(output)
end

-- 3. Audit Selected Packet / Session
local function menu_audit_packet()
    local win = TextWindow.new("Wi-Fi App Classifier: Selected Frame Audit")
    win:set_editable(false)

    local client = wlan_ta_f() and tostring(wlan_ta_f().value):lower() or nil
    local ra = wlan_ra_f() and tostring(wlan_ra_f().value):lower() or nil
    local bssid = wlan_bssid_f() and tostring(wlan_bssid_f().value):lower() or nil

    if not client then
        win:set("Please select an 802.11 Data frame in the packet list to audit.")
        return
    end

    local track = client_tracks[client] or client_tracks[ra]
    local report = {
        "================================================================================",
        "          802.11 Application Classifier — Selected Packet Audit",
        "================================================================================",
        string.format("Selected Frame Transmitter : %s", client),
        string.format("Selected Frame Receiver    : %s", ra or "N/A"),
        string.format("Target BSSID               : %s", bssid or "N/A"),
        "--------------------------------------------------------------------------------",
    }

    if track then
        local pred, conf = evaluate_track_baseline(track)
        table.insert(report, string.format("Observed Frames in Track   : %d", #track.frames))
        table.insert(report, string.format("Session Track ID           : %s:%03d", track.client_mac, track.session_ordinal))
        table.insert(report, string.format("Real-Time Prediction       : %s", pred or "N/A"))
        table.insert(report, string.format("Prediction Confidence      : %.1f%%", (conf or 0.0) * 100))
    else
        table.insert(report, "Session Track              : New client frame; window accumulating.")
    end

    table.insert(report, "================================================================================")
    win:set(table.concat(report, "\n"))
end

-- 4. Status & Benchmarks
local function menu_status_benchmarks()
    local win = TextWindow.new("Wi-Fi App Classifier: Pipeline Status")
    win:set_editable(false)
    win:append("Querying classifier engine, model catalog, and CM4 DUT status...\n\n")

    local output = run_helper_cmd("--status")
    local parsed = json.parse(output)
    if parsed then
        local lines = {
            "================================================================================",
            "          802.11 Raw Application Classifier — System Status",
            "================================================================================",
            string.format("Python Engine     : %s (%s)", parsed.python or "N/A", parsed.python_version or "N/A"),
            string.format("Torch Hardware    : %s (PyTorch %s)", parsed.torch_device or "CPU", parsed.torch_version or "N/A"),
            string.format("Active TCN Model  : %s", parsed.models and parsed.models.tcn or "None"),
            string.format("Baseline Weights  : %s", parsed.models and parsed.models.weights_json or "None"),
            "--------------------------------------------------------------------------------",
            string.format("CM4 DUT Host      : %s", parsed.cm4_dut and parsed.cm4_dut.host or "N/A"),
            string.format("CM4 State         : %s", parsed.cm4_dut and parsed.cm4_dut.details or "Offline"),
            "--------------------------------------------------------------------------------",
            "Cipher Support:",
            string.format("  • WPA2 (CCMP)   : %s", parsed.encryption_support and parsed.encryption_support.wpa2_ccmp or "Supported"),
            string.format("  • WPA3 (SAE)    : %s", parsed.encryption_support and parsed.encryption_support.wpa3_sae_ccmp or "Supported"),
            string.format("  • WPA3 (GCMP)   : %s", parsed.encryption_support and parsed.encryption_support.wpa3_sae_gcmp or "Supported"),
            "================================================================================",
        }
        win:set(table.concat(lines, "\n"))
    else
        win:set(output)
    end
end

-- Register GUI Menu Items
if register_menu then
    -- Tools Menu
    register_menu("Wi-Fi App Classifier/🎯 Classify Current Capture File", menu_classify_capture, MENU_TOOLS_UNSORTED)
    register_menu("Wi-Fi App Classifier/📡 Discover BSSIDs & Channels", menu_discover_bssids, MENU_TOOLS_UNSORTED)
    register_menu("Wi-Fi App Classifier/🔍 Audit Selected Packet & Session", menu_audit_packet, MENU_TOOLS_UNSORTED)
    register_menu("Wi-Fi App Classifier/⚡ Classifier Status & Benchmarks", menu_status_benchmarks, MENU_TOOLS_UNSORTED)

    -- Analyze Menu
    register_menu("Wi-Fi App Classifier/🎯 Classify Capture Windows", menu_classify_capture, MENU_ANALYZE_UNSORTED)
    register_menu("Wi-Fi App Classifier/🔍 Audit Selected Packet", menu_audit_packet, MENU_ANALYZE_UNSORTED)

    -- Context menu on right-click of packet
    if MENU_PACKET_ANALYZE_UNSORTED then
        register_menu("Wi-Fi App Classifier: Audit Packet & Session", menu_audit_packet, MENU_PACKET_ANALYZE_UNSORTED)
    end
end

print("[WiFi-App] Raw 802.11 Application Classifier extension loaded successfully (postdissector & AI tools registered).")
