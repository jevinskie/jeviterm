#include "jeviterm.h"
#include "iterm-api.pb.h"
#include "json.hpp"

#import <Foundation/Foundation.h>

#include <boost/asio/connect.hpp>
#include <boost/asio/local/stream_protocol.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <optional>
#include <string>

using namespace std::string_literals;

namespace jeviterm {

namespace beast     = boost::beast;                  // from <boost/beast.hpp>
namespace http      = beast::http;                   // from <boost/beast/http.hpp>
namespace websocket = beast::websocket;              // from <boost/beast/websocket.hpp>
namespace net       = boost::asio;                   // from <boost/asio.hpp>
using unix_fd = boost::asio::local::stream_protocol; // from <boost/asio/local/stream_protocol.hpp>

class iTermRPC {
public:
    static iTermRPC &shared_inst(const std::string &client_name) {
        static iTermRPC the_one_inst{client_name};
        return the_one_inst;
    }

    using window_id_t = std::string;

    int winid_str2int(const window_id_t &winid_str) {
        const auto idx = std::find(m_win_ids.cbegin(), m_win_ids.cend(), winid_str);
        if (idx != m_win_ids.cend()) {
            return std::distance(m_win_ids.cbegin(), idx) + 1; // 1 indexed, 0 reserved for new window
        }
        return JEVITERM_NONE_WINDOW_ID;
    }

    std::optional<window_id_t> winid_int2str(int winid_int) {
        // 1 indexed, 0 reserved for new window
        if (winid_int < 1 || winid_int > m_win_ids.size()) {
            return std::nullopt;
        }
        return m_win_ids[winid_int-1];
    }

    std::optional<window_id_t> create_tab(const char *cmd, const window_id_t *window = nullptr) {
        assert(cmd);

        const auto reqMsg     = get_create_tab_msg(cmd, window);
        const auto out_msg_sz = reqMsg.ByteSizeLong();
        beast::flat_buffer out_msg_buf{out_msg_sz};
        reqMsg.SerializeToArray(out_msg_buf.prepare(out_msg_sz).data(), out_msg_sz);
        out_msg_buf.commit(out_msg_sz);

        // Send the message
        m_ws.write(out_msg_buf.data());

        // This buffer will hold the incoming message
        beast::flat_buffer in_msg_buf;

        // Read a message into our buffer
        m_ws.read(in_msg_buf);

        // validate
        iterm2::ServerOriginatedMessage replyMsg;
        replyMsg.ParseFromArray(in_msg_buf.data().data(), in_msg_buf.size());
        if (!replyMsg.has_create_tab_response() || !replyMsg.create_tab_response().has_status() ||
            replyMsg.create_tab_response().status() != iterm2::CreateTabResponse_Status_OK ||
            !replyMsg.create_tab_response().has_window_id()) {
            return std::nullopt;
        }
        const auto win_id = replyMsg.create_tab_response().window_id();
        m_win_ids.push_back(win_id);
        return win_id;
    }

    struct CookieKey {
        std::string cookie;
        std::string key;
    };

    static const std::optional<CookieKey> &getCookieAndKey(const std::string &clientName,
                                                           bool force = false) {
        static std::optional<CookieKey> cookieKey{std::nullopt};
        if (!cookieKey || force) {
            NSDictionary<NSString *, id> *err = nil;
            NSAppleScript *get_stuff_as       = [[NSAppleScript alloc]
                initWithSource:
                    [NSString stringWithFormat:@"tell application \"iTerm2\" to request cookie "
                                                     @"and key for app named \"%s\"",
                                               clientName.c_str()]];
            NSAppleEventDescriptor *res_evt   = [get_stuff_as executeAndReturnError:&err];
            if (err) {
                std::cerr << "jeviterm AppleScript error: " <<
                    [NSString stringWithFormat:@"%@", err].UTF8String << "\n";
                return cookieKey;
            }
            NSArray<NSString *> *splitParts =
                [res_evt.stringValue componentsSeparatedByString:@" "];
            assert(splitParts.count == 2);
            cookieKey = CookieKey{.cookie = std::string{splitParts[0].UTF8String},
                                  .key    = std::string{splitParts[1].UTF8String}};
        }
        return cookieKey;
    }

    static std::string getSocketPath(void) {
        return std::string{[[[NSFileManager.defaultManager
                   URLsForDirectory:NSApplicationSupportDirectory
                          inDomains:NSUserDomainMask][0] path] UTF8String]} +
               "/iTerm2/private/socket";
    }

private:
    iTermRPC(const std::string &client_name)
        : m_client_name{client_name}, m_ws{m_ioc}, m_ep{getSocketPath()} {
        m_ws.binary(true);
        connect();
    }

    ~iTermRPC() {
        // FIXME: clean disconnect
        // disconnect();
    }

    bool connect() {
        const auto cookieKey = getCookieAndKey(m_client_name);
        if (!cookieKey) {
            std::cerr << "failed to get cookie and key from AppleScript\n";
            return false;
        }

        boost::beast::get_lowest_layer(m_ws).connect(m_ep);

        // Set a decorator to change the User-Agent of the handshake
        m_ws.set_option(websocket::stream_base::decorator([&](websocket::request_type &req) {
            req.set("origin", "ws://localhost/");
            req.set("host", "localhost");
            req.set("x-iterm2-library-version", "jeviterm 0.24");
            req.set("x-iterm2-disable-auth-ui", "false"); // FIXME: does this do anything?
            req.set("x-iterm2-cookie", cookieKey->cookie);
            req.set("x-iterm2-key", cookieKey->key);
            req.set("x-iterm2-advisory-name", m_client_name);
        }));

        // Perform the websocket handshake
        m_ws.handshake("api.iterm2.com", "/");
        return true;
    }

    bool disconnect() {
        // FIXME: throws even on good nominal disconnect?
        m_ws.close(websocket::close_code::normal);
        return true;
    }

    iterm2::ClientOriginatedMessage get_create_tab_msg(std::string cmd,
                                                       const window_id_t *window = nullptr) {
        iterm2::ClientOriginatedMessage reqMsg;

        iterm2::CreateTabRequest ctReqMsg;
        auto cstCmdProp = ctReqMsg.add_custom_profile_properties();
        cstCmdProp->set_key("Custom Command");
        cstCmdProp->set_json_value("\"Yes\"");
        auto cmdProp = ctReqMsg.add_custom_profile_properties();
        cmdProp->set_key("Command");
        // nlohmann::json json_cmd_str = cmd;
        nlohmann::json json_cmd_str = cmd;
        cmdProp->set_json_value(json_cmd_str.dump()); // serialize/escape command string
        if (window) {
            ctReqMsg.set_window_id(*window);
        }
        *reqMsg.mutable_create_tab_request() = ctReqMsg;

        return reqMsg;
    }

private:
    std::string m_client_name;
    net::io_context m_ioc;
    unix_fd::endpoint m_ep;
    websocket::stream<unix_fd::socket> m_ws;
    std::vector<std::string> m_win_ids; // will not be thread safe
};

} // namespace jeviterm

using namespace jeviterm;

__attribute__((visibility("default"))) int jeviterm_open_tabs(const char **cmds, int same_window,
                                                              int window_id, const char *client_name) {
    if (!cmds) {
        return 1;
    }
    if (client_name == nullptr) {
        client_name = "jeviterm";
    }
    try {
        auto &rpc = iTermRPC::shared_inst(client_name);
        iTermRPC::window_id_t existing_window_id;
        const auto str_winid = rpc.winid_int2str(window_id);
        if (str_winid) {
            existing_window_id = *str_winid;
        }
        std::optional<iTermRPC::window_id_t> new_window_id;
        for (const char **cmdp = cmds; *cmdp != nullptr; ++cmdp) {
            new_window_id = rpc.create_tab(*cmdp, existing_window_id.empty() ? nullptr : &existing_window_id);
            if (new_window_id && same_window) {
                existing_window_id = *new_window_id;
            }
        }
        return rpc.winid_str2int(new_window_id ? *new_window_id : "");
    } catch (std::exception const &e) {
        std::cerr << "jeviterm_open_tabs error: " << e.what() << "\n";
        return JEVITERM_NONE_WINDOW_ID;
    }
}

__attribute__((visibility("default"))) int jeviterm_open_tabs2(const char **cmds, int same_window,
                                                               const char *client_name) {
    if (!cmds) {
        return 1;
    }
    if (client_name == nullptr) {
        client_name = "jeviterm";
    }

    fprintf(stderr, "HELLO spawning gui here\n");
    static int last_win_id = JEVITERM_NONE_WINDOW_ID;
    for (const char **cmdp = cmds; *cmdp != nullptr; ++cmdp) {
        const char *cmds_single[] = {*cmdp, NULL};
        last_win_id = jeviterm_open_tabs(cmds_single, 1, last_win_id, client_name);
    }
    return last_win_id;
}

__attribute__((visibility("default"))) const char *jeviterm_version(void) {
    static std::string res;
    if (res.empty()) {
        res += "jeviterm version " JEVITERM_VERSION "\n";
        if (JEVITERM_GIT_RETRIEVED_STATE) {
            if (JEVITERM_GIT_IS_DIRTY)
                res += "WARN: there were uncommitted changes.\n";

            // Print information about the commit.
            // The format imitates the output from "git log".
            res += "commit " JEVITERM_GIT_HEAD_SHA1 " (HEAD)\n"
                   "Describe: " JEVITERM_GIT_DESCRIBE "\n"
                   "Date: " JEVITERM_GIT_COMMIT_DATE_ISO8601;
        }
    }
    return res.c_str();
}
