#include "jeviterm.h"
#include "iterm-api.pb.h"

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <optional>
#include <string>
#include <system_error>
#include <unistd.h>

#import <Foundation/Foundation.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#include <boost/asio/connect.hpp>
#pragma clang diagnostic pop
#include <boost/asio/local/stream_protocol.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <nlohmann/json.hpp>

using namespace std::string_literals;

// AppleScript hack
__attribute__((constructor)) static void run_CurrentThreadIsMainOrCooperative_on_main_thread() {
    static std::once_flag flag;
    std::call_once(flag, []() {
        // parts of AppleScript need to be primed on the main thread
        if (!NSThread.isMainThread) {
            dispatch_sync(dispatch_get_main_queue(),
                          ^{ [[NSAppleScript.alloc initWithSource:@"\"\""] executeAndReturnError:nil]; });
        } else {
            // already on main thread
            [[NSAppleScript.alloc initWithSource:@"\"\""] executeAndReturnError:nil];
        }
    });
}

namespace jeviterm {

namespace beast     = boost::beast;                        // from <boost/beast.hpp>
namespace http      = beast::http;                         // from <boost/beast/http.hpp>
namespace websocket = beast::websocket;                    // from <boost/beast/websocket.hpp>
namespace net       = boost::asio;                         // from <boost/asio.hpp>
using unix_fd       = boost::asio::local::stream_protocol; // from <boost/asio/local/stream_protocol.hpp>

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
        return m_win_ids.at(winid_int - 1);
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

private:
    struct CookieKey {
        std::string cookie;
        std::string key;
    };

    static const std::optional<CookieKey> getCookieAndKey(const std::string &clientName) {
        NSDictionary<NSString *, id> *err = nil;
        NSAppleScript *get_stuff_as       = [NSAppleScript.alloc
            initWithSource:[NSString stringWithFormat:@"tell application \"iTerm2\" to request cookie "
                                                            @"and key for app named \"%s\"",
                                                      clientName.c_str()]];
        // std::cerr << "before prime\n";
        // std::cerr << "after prime\n";
        // std::cerr << "before as exec\n";
        NSAppleEventDescriptor *res_evt = [get_stuff_as executeAndReturnError:&err];
        // std::cerr << "after as exec\n";
        if (err) {
            fprintf(stderr, "jeviterm AppleScript error: '%s'\n", [NSString stringWithFormat:@"%@", err].UTF8String);
            return std::nullopt;
        }
        NSArray<NSString *> *splitParts = [res_evt.stringValue componentsSeparatedByString:@" "];
        assert(splitParts.count == 2);
        return CookieKey{.cookie = std::string{splitParts[0].UTF8String}, .key = std::string{splitParts[1].UTF8String}};
    }

    static std::string getSocketPath(void) {
        auto r = std::string{[NSFileManager.defaultManager URLsForDirectory:NSApplicationSupportDirectory
                                                                  inDomains:NSUserDomainMask][0].path.UTF8String} +
                 "/iTerm2/private/socket";
        fprintf(stderr, "getSocketPath: '%s'\n", r.c_str());
        return r;
    }

    iTermRPC(const std::string &client_name)
        : m_client_name{client_name}, m_cookie_key{getCookieAndKey(client_name)}, m_ws{m_ioc}, m_ep{getSocketPath()} {
        m_ws.binary(true);
        connect();
    }

    ~iTermRPC() {
        // FIXME: clean disconnect
        // disconnect();
    }

    bool connect() {
        // std::cerr << "connect\n";
        if (!m_cookie_key) {
            fprintf(stderr, "failed to get cookie and key from AppleScript\n");
            return false;
        }
        // std::cerr << "got cookie and key\n";

        boost::beast::get_lowest_layer(m_ws).connect(m_ep);

        // Set a decorator to change the User-Agent of the handshake
        m_ws.set_option(websocket::stream_base::decorator([&](websocket::request_type &req) {
            req.set("origin", "ws://localhost/");
            req.set("host", "localhost");
            req.set("x-iterm2-library-version", "jeviterm 0.1.8");
            req.set("x-iterm2-disable-auth-ui", "false"); // FIXME: does this do anything?
            req.set("x-iterm2-cookie", m_cookie_key->cookie);
            req.set("x-iterm2-key", m_cookie_key->key);
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

    iterm2::ClientOriginatedMessage get_create_tab_msg(std::string cmd, const window_id_t *window = nullptr) {
        iterm2::ClientOriginatedMessage reqMsg;

        iterm2::CreateTabRequest ctReqMsg;
        auto cstCmdProp = ctReqMsg.add_custom_profile_properties();
        cstCmdProp->set_key("Custom Command");
        cstCmdProp->set_json_value("\"Yes\"");
        auto cmdProp = ctReqMsg.add_custom_profile_properties();
        cmdProp->set_key("Command");
        nlohmann::json json_cmd_str = cmd;
        cmdProp->set_json_value(json_cmd_str.dump()); // serialize/escape command string
        if (window) {
            ctReqMsg.set_window_id(*window);
        }
        *reqMsg.mutable_create_tab_request() = ctReqMsg;

        return reqMsg;
    }

private:
    const std::string m_client_name;
    const std::optional<CookieKey> m_cookie_key;
    net::io_context m_ioc;
    unix_fd::endpoint m_ep;
    websocket::stream<unix_fd::socket> m_ws;
    std::vector<std::string> m_win_ids; // FIXME: will not be thread safe
};

} // namespace jeviterm

using namespace jeviterm;

static int open_tabs_helper(const char **cmds, int same_window, int window_id, iTermRPC &rpc) {
    // std::cerr << "got rpc shared inst\n";
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
}

__attribute__((visibility("default"))) int jeviterm_open_tabs(const char **cmds, int same_window, int window_id,
                                                              const char *client_name) {
    if (!cmds) {
        return 1;
    }
    if (client_name == nullptr) {
        client_name = "jeviterm";
    }
    try {
        // call this to stash the cookie/key because AppleScript doesn't like to run after forking?
        // auto &rpc                    = iTermRPC::shared_inst(client_name);
        const auto sudo_uid_nsstring = NSProcessInfo.processInfo.environment[@"SUDO_UID"];
        pid_t child_pid;
        fprintf(stderr, "sudo_uid_nsstring: %p '%s'\n", sudo_uid_nsstring,
                sudo_uid_nsstring ? sudo_uid_nsstring.UTF8String : "(nil)");
        if (sudo_uid_nsstring) {
            assert(!"sudo_uid_nsstring is present, would fork normally (can't remember why)");
            const auto sudo_uid = std::stoi(std::string{sudo_uid_nsstring.UTF8String});
            int pipefd[2];
            if (pipe(pipefd) == -1) {
                throw std::system_error{std::error_code(errno, std::generic_category()), strerror(errno)};
            }
            auto &rpc = iTermRPC::shared_inst(client_name);
            child_pid = fork();
            if (child_pid == -1) {
                throw std::system_error{std::error_code(errno, std::generic_category()), strerror(errno)};
            }
            if (!child_pid) {
                // this is child
                // std::cerr << "in child pid: " << getpid() << "\n";
                if (seteuid(sudo_uid) == -1) {
                    throw std::system_error{std::error_code(errno, std::generic_category()), strerror(errno)};
                }
                // std::cerr << "child before open_tabs_helper\n";
                const auto new_win_id = open_tabs_helper(cmds, same_window, window_id, rpc);
                // std::cerr << "child new_win_id: " << new_win_id << "\n";
                const auto write_res = write(pipefd[1], &new_win_id, sizeof(new_win_id));
                // std::cerr << "child write_res: " << write_res << "\n";
                if (write_res == -1) {
                    throw std::system_error{std::error_code(errno, std::generic_category()), strerror(errno)};
                } else if (write_res != sizeof(new_win_id)) {
                    throw std::system_error{std::error_code(EPIPE, std::generic_category()),
                                            "couldn't write new window id from child"};
                }
                exit(0);
            } else {
                // this is parent
                int child_status;
                int new_win_id;
                int read_res;
                do {
                    errno    = 0;
                    read_res = read(pipefd[0], &new_win_id, sizeof(new_win_id));
                } while (read_res == -1 && (errno == EAGAIN || errno == EINTR));
                // std::cerr << "read finished id: " << new_win_id << " res: " << read_res << "\n";
                if (read_res == -1) {
                    throw std::system_error{std::error_code(errno, std::generic_category()), strerror(errno)};
                } else if (read_res != sizeof(new_win_id)) {
                    throw std::system_error{std::error_code(EPIPE, std::generic_category()),
                                            "couldn't read new window id from parent"};
                }
                int waitpid_res;
                do {
                    errno       = 0;
                    waitpid_res = waitpid(child_pid, &child_status, 0);
                } while (waitpid_res == -1 && (errno == EAGAIN || errno == EINTR));
                if (waitpid_res == -1) {
                    throw std::system_error{std::error_code(errno, std::generic_category()), strerror(errno)};
                }
                return new_win_id;
            }
        } else {
            auto &rpc = iTermRPC::shared_inst(client_name);
            return open_tabs_helper(cmds, same_window, window_id, rpc);
        }
    } catch (std::exception const &e) {
        fprintf(stderr, "jeviterm_open_tabs error: '%s'\n", e.what());
        return JEVITERM_NONE_WINDOW_ID;
    }
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
