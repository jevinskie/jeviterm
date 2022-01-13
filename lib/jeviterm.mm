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

namespace beast     = boost::beast;                  // from <boost/beast.hpp>
namespace http      = beast::http;                   // from <boost/beast/http.hpp>
namespace websocket = beast::websocket;              // from <boost/beast/websocket.hpp>
namespace net       = boost::asio;                   // from <boost/asio.hpp>
using unix_fd = boost::asio::local::stream_protocol; // from <boost/asio/local/stream_protocol.hpp>

struct CookieKey {
    std::string cookie;
    std::string key;
};

std::optional<CookieKey> getCookieAndKey(std::string clientName) {
    NSDictionary<NSString *, id> *err = nil;
    NSAppleScript *get_stuff_as       = [[NSAppleScript alloc]
        initWithSource:[NSString stringWithFormat:@"tell application \"iTerm2\" to request cookie "
                                                        @"and key for app named \"%s\"",
                                                  clientName.c_str()]];
    NSAppleEventDescriptor *res_evt   = [get_stuff_as executeAndReturnError:&err];
    if (err) {
        NSLog(@"AppleScript error: %@", err);
        return std::nullopt;
    }
    NSArray<NSString *> *splitParts = [res_evt.stringValue componentsSeparatedByString:@" "];
    assert(splitParts.count == 2);
    return CookieKey{.cookie = std::string{splitParts[0].UTF8String},
                     .key    = std::string{splitParts[1].UTF8String}};
}

std::string getSocketPath(void) {
    return std::string{[[[NSFileManager.defaultManager
               URLsForDirectory:NSApplicationSupportDirectory
                      inDomains:NSUserDomainMask][0] path] UTF8String]} +
           "/iTerm2/private/socket";
}

void hexdump(void *buf, std::size_t sz) {
    for (const uint8_t *p = (const uint8_t *)buf; p < (const uint8_t *)buf + sz; ++p) {
        std::cerr << std::setfill('0') << std::setw(2) << std::hex << (unsigned int)*p;
    }
}

// Sends a WebSocket message and prints the response
int demo_main(std::string clientName) {
    const auto cookieKey = getCookieAndKey(clientName);
    if (!cookieKey) {
        std::cerr << "failed to get cookie and key from AppleScript\n";
        return -1;
    }
    std::cerr << "cookie: " << cookieKey->cookie << " key: " << cookieKey->key << "\n";
    try {
        // The io_context is required for all I/O
        net::io_context ioc;

        // These objects perform our I/O
        const auto sockPath = getSocketPath();
        std::cerr << "sockPath: " << sockPath << "\n";
        auto ep = unix_fd::endpoint{sockPath};
        websocket::stream<unix_fd::socket> ws{ioc};
        std::cerr << "ws obj created\n";
        ws.binary(true);

        // Make the connection on the IP address we get from a lookup
        boost::beast::get_lowest_layer(ws).connect(ep);
        std::cerr << "connected\n";

        // Set a decorator to change the User-Agent of the handshake
        ws.set_option(websocket::stream_base::decorator([&](websocket::request_type &req) {
            req.set("origin", "ws://localhost/");
            req.set("host", "localhost");
            req.set("x-iterm2-library-version", "python 0.24");
            req.set("x-iterm2-disable-auth-ui", "true");
            req.set("x-iterm2-cookie", cookieKey->cookie);
            req.set("x-iterm2-key", cookieKey->key);
            req.set("x-iterm2-advisory-name", clientName);
        }));

        // Perform the websocket handshake
        ws.handshake("api.iterm2.com", "/");

        iterm2::ClientOriginatedMessage reqMsg;

        // iterm2::FocusRequest focReqMsg;
        // reqMsg.set_allocated_focus_request(&focReqMsg);

        // iterm2::ProfileProperty cmdProp;
        // cmdProp.set_key("Command");
        // cmdProp.set_json_value("/usr/bin/env bash -l -c vi");

        iterm2::CreateTabRequest ctReqMsg;
        auto cstCmdProp = ctReqMsg.add_custom_profile_properties();
        cstCmdProp->set_key("Custom Command");
        cstCmdProp->set_json_value("\"Yes\"");
        auto cmdProp = ctReqMsg.add_custom_profile_properties();
        cmdProp->set_key("Command");
        cmdProp->set_json_value("\"/usr/bin/env bash -l -c vi\"");
        // ctReqMsg.set_command("/usr/bin/env bash -l -c vi");
        *reqMsg.mutable_create_tab_request() = ctReqMsg;

        const auto out_msg_sz = reqMsg.ByteSizeLong();
        // std::vector<uint8_t> out_msg_buf;
        // out_msg_buf.resize(out_msg_sz);
        // reqMsg.SerializeToArray(out_msg_buf.data(), out_msg_buf.size());
        beast::flat_buffer out_msg_buf{out_msg_sz};
        reqMsg.SerializeToArray(out_msg_buf.prepare(out_msg_sz).data(), out_msg_sz);
        out_msg_buf.commit(out_msg_sz);
        std::cerr << "out_msg_sz: " << out_msg_sz << " buf sz: " << out_msg_buf.size() << "\n";
        std::cerr << "out_msg_buf: ";
        hexdump(out_msg_buf.data().data(), out_msg_buf.size());
        std::cerr << "\n";

        // return 0;

        std::cerr << "write begin\n";
        // Send the message
        // ws.write(beast::flat_buffer{out_msg_buf.data(), out_msg_buf.size()});
        ws.write(out_msg_buf.data());
        std::cerr << "write end\n";

        // This buffer will hold the incoming message
        beast::flat_buffer buffer;

        for (int loopnum = 0; loopnum < 1; ++loopnum) {
            // Read a message into our buffer
            std::cerr << "read begin\n";
            ws.read(buffer);
            std::cerr << "read end\n";
            std::cout << "read n bytes: " << buffer.size() << "\n";

            // The make_printable() function helps print a ConstBufferSequence
            // std::cout << beast::make_printable(buffer.data()) << "\n";
        }

        // sleep(5);

        std::cerr << "close begin\n";
        // Close the WebSocket connection
        ws.close(websocket::close_code::normal);
        std::cerr << "close end\n";

        // If we get here then the connection is closed gracefully

        // The make_printable() function helps print a ConstBufferSequence
        // std::cout << beast::make_printable(buffer.data()) << "\n";
    } catch (std::exception const &e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

__attribute__((visibility("default")))
void doit(void) {
    NSLog(@"Just Do It");
    demo_main("jevitermtest");
}
