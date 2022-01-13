#include "jeviterm.h"
#include "iterm-api.pb.h"

#import <Foundation/Foundation.h>

#include <boost/asio/connect.hpp>
#include <boost/asio/local/stream_protocol.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <cstdlib>
#include <iostream>
#include <string>
#include <optional>

namespace beast     = boost::beast;         // from <boost/beast.hpp>
namespace http      = beast::http;          // from <boost/beast/http.hpp>
namespace websocket = beast::websocket;     // from <boost/beast/websocket.hpp>
namespace net       = boost::asio;          // from <boost/asio.hpp>
using unix_fd       = boost::asio::local::stream_protocol; // from <boost/asio/local/stream_protocol.hpp>

struct CookieKey {
    std::string cookie;
    std::string key;
};

std::optional<CookieKey> getCookieAndKey(std::string clientName) {
    NSDictionary<NSString *, id> *err = nil;
    NSAppleScript *get_stuff_as = [[NSAppleScript alloc] initWithSource:[NSString stringWithFormat:@"tell application \"iTerm2\" to request cookie and key for app named \"%s\"", clientName.c_str()]];
    NSAppleEventDescriptor *res_evt = [get_stuff_as executeAndReturnError:&err];
    if (err) {
        NSLog(@"AppleScript error: %@", err);
        return std::nullopt;
    }
    NSArray<NSString *> *splitParts = [res_evt.stringValue componentsSeparatedByString: @" "];
    assert(splitParts.count == 2);
    return CookieKey{.cookie = std::string{splitParts[0].UTF8String}, .key = std::string{splitParts[1].UTF8String}};
}

std::string getSocketPath(void) {
    return std::string{[[[NSFileManager.defaultManager URLsForDirectory:NSApplicationSupportDirectory inDomains:NSUserDomainMask][0] path] UTF8String]} + "/iTerm2/private/socket";
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

        iterm2::FocusRequest focReqMsg;
        // *reqMsg.mutable_focus_request() = focReqMsg;

        iterm2::CreateTabRequest ctReqMsg;
        *reqMsg.mutable_create_tab_request() = ctReqMsg;

        const auto out_msg_sz = reqMsg.ByteSizeLong();
        // std::vector<uint8_t> out_msg_buf;
        // out_msg_buf.resize(out_msg_sz);
        // reqMsg.SerializeToArray(out_msg_buf.data(), out_msg_buf.size());
        beast::flat_buffer out_msg_buf{out_msg_sz};
        reqMsg.SerializeToArray(out_msg_buf.prepare(out_msg_buf.size()).data(), out_msg_buf.size());
        std::cerr << "out_msg_sz: " << out_msg_sz << "\n";
        std::cerr << "out_msg_buf: " << beast::make_printable(out_msg_buf.data()) << "\n";

        // Send the message
        // ws.write(beast::flat_buffer{out_msg_buf.data(), out_msg_buf.size()});
        ws.write(out_msg_buf.data());

        // This buffer will hold the incoming message
        beast::flat_buffer buffer;

        for (int loopnum = 0; loopnum < 2; ++loopnum) {
            // Read a message into our buffer
            ws.read(buffer);
            std::cout << "read n bytes: " << buffer.size() << "\n";

            // The make_printable() function helps print a ConstBufferSequence
            std::cout << beast::make_printable(buffer.data()) << "\n";
        }

        // Close the WebSocket connection
        ws.close(websocket::close_code::normal);

        // If we get here then the connection is closed gracefully

        // The make_printable() function helps print a ConstBufferSequence
        std::cout << beast::make_printable(buffer.data()) << "\n";
    } catch (std::exception const &e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

void doit(void) {
    NSLog(@"Just Do It");
    demo_main("jevitermtest");
}
