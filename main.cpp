#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/strand.hpp>
#include <boost/config.hpp>
#include <boost/json/src.hpp>

#include <boost/bind.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/asio.hpp>


#include <iostream>
#include <memory>
#include <string>
#include <thread>

namespace beast = boost::beast; // from <boost/beast.hpp>
namespace http = beast::http;   // from <boost/beast/http.hpp>
namespace net = boost::asio;    // from <boost/asio.hpp>
using tcp = net::ip::tcp;       // from <boost/asio/ip/tcp.hpp>
using namespace boost::json;    // from <boost/json/src.hpp> // Without library link (self-contained)

// This function produces an HTTP response for the given request.
http::response<http::string_body> handle_request(http::request<http::string_body> const& req) {
    std::cout << "[Request] - " << req << std::endl;
    // GET
    if (req.method() == http::verb::get && req.target() == "/api/data") {
        // Handle GET request
        boost::json::value json_response = {{"message", "GET request"}};
        http::response<http::string_body> res{http::status::ok, req.version()};
        res.set(http::field::server, "Beast");
        res.set(http::field::content_type, "application/json");
        res.keep_alive(req.keep_alive());
        res.body() = boost::json::serialize( json_response );
        res.prepare_payload();
        return res;
    } else
        // POST
    if (req.method() == http::verb::post && req.target() == "/api/data") {
        // Handle POST request
        auto json_request = boost::json::parse(req.body());
        std::string response_message = "POST: " + boost::json::serialize(json_request);
        boost::json::value json_response = {{"message",response_message}};
        http::response<http::string_body> res{http::status::ok, req.version()};
        res.set(http::field::server, "Beast");
        res.set(http::field::content_type, "application/json");
        res.keep_alive(req.keep_alive());
        res.body() = boost::json::serialize( json_response );
        res.prepare_payload();
        return res;
    } else
        // PUT
    if (req.method() == http::verb::put && req.target() == "/api/data") {
        // Handle PUT request
        boost::json::value json_request = boost::json::parse(req.body());
        std::string response_message = "PUT" + boost::json::serialize(json_request);
        boost::json::value json_response = {{"message", response_message}};
        http::response<http::string_body> res{http::status::ok, req.version()};
        res.set(http::field::server, "Beast");
        res.set(http::field::content_type, "application/json");
        res.keep_alive(req.keep_alive());
        res.body() = boost::json::serialize(json_response);
        res.prepare_payload();
        return res;
    } else
        // PATCH
    if(req.method() == http::verb::patch && req.target() == "/api/data") {
        // Handle PATCH request
        boost::json::value json_request = boost::json::parse(req.body());
        std::string response_message = "PATCH" + boost::json::serialize(json_request);
        boost::json::value json_response = {{"message", response_message}};
        http::response<http::string_body> res{http::status::ok, req.version()};
        res.set(http::field::server, "Beast");
        res.set(http::field::content_type, "application/json");
        res.keep_alive(req.keep_alive());
        res.body() = boost::json::serialize(json_response);
        res.prepare_payload();
        return res;
    } else
        // DELETE
    if (req.method() == http::verb::delete_ && req.target() == "/api/data") {
        // Handle DELETE request
        boost::json::value json_response = {{"DELETE","Resource deleted"}};
        http::response<http::string_body> res{http::status::ok, req.version()};
        res.set(http::field::server, "Beast");
        res.set(http::field::content_type, "application/json");
        res.keep_alive(req.keep_alive());
        res.body() = boost::json::serialize( json_response );
        res.prepare_payload();
        return res;
    }

    // Default response for unsupported methods
    return http::response<http::string_body>{http::status::bad_request, req.version()};
}

// This class handles an HTTP server connection.
class Session : public boost::enable_shared_from_this<Session> {
    tcp::socket socket_;
    beast::flat_buffer buffer_;
    http::request<http::string_body> req_;

public:
    explicit Session(tcp::socket socket) : socket_(std::move(socket)) {}

    void run() {
        std::cout << std::endl << "#################################" << std::endl;
        std::cout << "Opening session!" << std::endl;
        std::cout << "#################################" << std::endl;
        do_read();
    }

private:
    void do_read() {
        std::cout << " <<< Reading request" << std::endl;
        auto self(shared_from_this());
        http::async_read(socket_, buffer_, req_, [this, self](beast::error_code ec, std::size_t) {
            if (!ec) {
                do_write(handle_request(req_));
            }
        });
    }

    void do_write(http::response<http::string_body> res) {
        std::cout << " >>> Writing response" << std::endl;
        auto self(shared_from_this());

        std::cout << res << std::endl;
        auto sp = boost::make_shared<http::response<http::string_body>>(std::move(res));
        http::async_write(socket_, *sp, [this, self, sp](beast::error_code ec, std::size_t) {
            socket_.shutdown(tcp::socket::shutdown_send, ec);
        });
    }
};

// This class accepts incoming connections and launches the sessions.
class Listener : public boost::enable_shared_from_this<Listener> {
    net::io_context& ioc_;
    tcp::acceptor acceptor_;

public:
    Listener(net::io_context& ioc, tcp::endpoint endpoint)
        : ioc_(ioc), acceptor_(net::make_strand(ioc)) {
        beast::error_code ec;

        // Open the acceptor
        acceptor_.open(endpoint.protocol(), ec);
        if (ec) {
            std::cerr << "Open error: " << ec.message() << std::endl;
            return;
        }
        // Allow address reuse
        acceptor_.set_option(net::socket_base::reuse_address(true), ec);
        if (ec) {
            std::cerr << "Set option error: " << ec.message() << std::endl;
            return;
        }
        // Bind to the server address
        acceptor_.bind(endpoint, ec);
        if (ec) {
            std::cerr << "Bind error: " << ec.message() << std::endl;
            return;
        }
        // Start listening for connections
        acceptor_.listen(net::socket_base::max_listen_connections, ec);
        if (ec) {
            std::cerr << "Listen error: " << ec.message() << std::endl;
            return;
        }
//       do_accept();
    }

//private:
    void do_accept() {
        acceptor_.async_accept(net::make_strand(ioc_),
                               [this](beast::error_code ec, tcp::socket socket) {
            if (!ec) {
                boost::make_shared<Session>(std::move(socket))->run();
            }
            do_accept();
        });
    }

};

int main() {
    try {
        auto const address = net::ip::make_address("127.0.0.1");
        unsigned short port = 8080;

        net::io_context ioc{1};

        auto list = std::make_shared<Listener>(ioc, tcp::endpoint{address, port});
        list->do_accept();
        std::cout << ">>>>>>> SERVER ONLINE <<<<<<<<" << std::endl;
        ioc.run();
    } catch (const std::exception& e) {
        std::cerr << "Exceção: " << e.what() << std::endl;
    }
}
