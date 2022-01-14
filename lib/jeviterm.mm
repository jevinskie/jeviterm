#include "jeviterm.h"
#include "iterm-api.pb.h"

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


static void hexdump(void *buf, std::size_t sz) {
    for (const uint8_t *p = (const uint8_t *)buf; p < (const uint8_t *)buf + sz; ++p) {
        std::cerr << std::setfill('0') << std::setw(2) << std::hex << (unsigned int)*p;
    }
}

class iTermRPC {
public:
    iTermRPC(std::string client_name) : m_client_name{client_name}, m_ws{m_ioc}, m_ep{getSocketPath()} {
        m_ws.binary(true);
        if (!connect()) {
        }
    }

    ~iTermRPC() {
        disconnect();
    }

    bool create_tab(const char *cmd) {
        assert(cmd);

        const auto reqMsg = get_create_tab_msg(cmd);
        const auto out_msg_sz = reqMsg.ByteSizeLong();
        beast::flat_buffer out_msg_buf{out_msg_sz};
        reqMsg.SerializeToArray(out_msg_buf.prepare(out_msg_sz).data(), out_msg_sz);
        out_msg_buf.commit(out_msg_sz);

        std::cerr << "write begin\n";
        // Send the message
        // ws.write(beast::flat_buffer{out_msg_buf.data(), out_msg_buf.size()});
        m_ws.write(out_msg_buf.data());
        std::cerr << "write end\n";

        // This buffer will hold the incoming message
        beast::flat_buffer in_msg_buf;

        // Read a message into our buffer
        std::cerr << "read begin\n";
        m_ws.read(in_msg_buf);
        std::cerr << "read end\n";
        std::cerr << "read n bytes: " << in_msg_buf.size() << "\n";

        iterm2::ServerOriginatedMessage replyMsg;
        replyMsg.ParseFromArray(in_msg_buf.data().data(), in_msg_buf.size());
        std::cerr << "replyMsg: " << replyMsg.DebugString() << "\n";
        if (!replyMsg.has_create_tab_response() || replyMsg.create_tab_response().status() != iterm2::CreateTabResponse_Status_OK) {
            return false;
        }
        return true;
    }

    struct CookieKey {
        std::string cookie;
        std::string key;
    };

    static const std::optional<CookieKey> &getCookieAndKey(std::string clientName, bool force = false) {
        static std::optional<CookieKey> cookieKey{std::nullopt};
        if (!cookieKey || force) {
            NSDictionary<NSString *, id> *err = nil;
            NSAppleScript *get_stuff_as       = [[NSAppleScript alloc]
                initWithSource:[NSString
                                   stringWithFormat:@"tell application \"iTerm2\" to request cookie "
                                                          @"and key for app named \"%s\"",
                                                    clientName.c_str()]];
            NSAppleEventDescriptor *res_evt   = [get_stuff_as executeAndReturnError:&err];
            if (err) {
                std::cerr << "AppleScript error: " << [NSString stringWithFormat:@"%@", err].UTF8String << "\n";
                return cookieKey;
            }
            NSArray<NSString *> *splitParts = [res_evt.stringValue componentsSeparatedByString:@" "];
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
    bool connect() {
        const auto cookieKey = getCookieAndKey(m_client_name);
        if (!cookieKey) {
            std::cerr << "failed to get cookie and key from AppleScript\n";
            return false;
        }

        std::cerr << "connecting\n";
        // Make the connection on the IP address we get from a lookup
        boost::beast::get_lowest_layer(m_ws).connect(m_ep);
        std::cerr << "connected\n";

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
        std::cerr << "close begin\n";
        // Close the WebSocket connection
        m_ws.close(websocket::close_code::normal);
        std::cerr << "close end\n";
        return true;
    }

    iterm2::ClientOriginatedMessage get_create_tab_msg(std::string cmd) {
        iterm2::ClientOriginatedMessage reqMsg;

        iterm2::CreateTabRequest ctReqMsg;
        auto cstCmdProp = ctReqMsg.add_custom_profile_properties();
        cstCmdProp->set_key("Custom Command");
        cstCmdProp->set_json_value("\"Yes\"");
        auto cmdProp = ctReqMsg.add_custom_profile_properties();
        cmdProp->set_key("Command");
        cmdProp->set_json_value("\"" + cmd + "\"");
        *reqMsg.mutable_create_tab_request() = ctReqMsg;

        return reqMsg;
    }

private:
    net::io_context m_ioc;
    unix_fd::endpoint m_ep;
    websocket::stream<unix_fd::socket> m_ws;
    std::string m_client_name;
};

} // namespace jeviterm

__attribute__((visibility("default")))
int jeviterm_open_tabs(const char **cmds, const char *client_name) {
    bool good = true;
    if (!cmds) {
        return 1;
    }
    if (client_name == nullptr) {
        client_name = "jeviterm";
    }
    try {
        jeviterm::iTermRPC rpc{client_name};
        for (const char **cmdp = cmds; *cmdp != nullptr; ++cmdp) {
            good &= rpc.create_tab(*cmdp);
        }
    } catch (std::exception const &e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return !good; // 0 on success
}

__attribute__((visibility("default"))) void doit(void) {
    const char *cmds[] = {"/usr/bin/env bash -l -c vi", "/usr/bin/env bash -l -c nano", nullptr};
    jeviterm_open_tabs(cmds, "jevitermtest");
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

