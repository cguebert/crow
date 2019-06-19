#pragma once
#include <boost/asio.hpp>
#ifdef CROW_ENABLE_SSL
#include <boost/asio/ssl.hpp>
#endif
#include "crow/settings.h"
namespace crow
{
    using namespace boost;
    using tcp = asio::ip::tcp;

    struct SocketAdaptor
    {
        using context = void;
        SocketAdaptor(boost::asio::io_context& io_context, context*)
            : socket_(io_context)
        {
        }

        boost::asio::executor get_executor()
        {
            return socket_.get_executor();
        }

        tcp::socket& raw_socket()
        {
            return socket_;
        }

        tcp::socket& socket()
        {
            return socket_;
        }

        tcp::endpoint remote_endpoint()
        {
            return socket_.remote_endpoint();
        }

        bool is_open()
        {
            return socket_.is_open();
        }

        void close()
        {
            boost::system::error_code ec;
            socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
            socket_.close(ec);
        }

        template <typename F> 
        void start(F f)
        {
            f(boost::system::error_code());
        }

        tcp::socket socket_;
    };

#ifdef CROW_ENABLE_SSL
    struct SSLAdaptor
    {
        using context = boost::asio::ssl::context;
        using ssl_socket_t = boost::asio::ssl::stream<tcp::socket>;
        SSLAdaptor(boost::asio::io_context& io_context, context* ctx)
            : ssl_socket_(new ssl_socket_t(io_context, *ctx))
        {
        }

        boost::asio::ssl::stream<tcp::socket>& socket()
        {
            return *ssl_socket_;
        }

        tcp::socket::lowest_layer_type&
        raw_socket()
        {
            return ssl_socket_->lowest_layer();
        }

        tcp::endpoint remote_endpoint()
        {
            return raw_socket().remote_endpoint();
        }

        bool is_open()
        {
            return ssl_socket_ ? raw_socket().is_open() : false;
        }

        void close()
        {
            if (!ssl_socket_)
                return;

            boost::system::error_code ec;
            raw_socket().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
            raw_socket().close(ec);
        }

        boost::asio::executor& get_executor()
        {
            return raw_socket().get_executor();
        }

        template <typename F> 
        void start(F f)
        {
            ssl_socket_->async_handshake(boost::asio::ssl::stream_base::server,
                    [f](const boost::system::error_code& ec) {
                        f(ec);
                    });
        }

        std::unique_ptr<boost::asio::ssl::stream<tcp::socket>> ssl_socket_;
    };
#endif
}
