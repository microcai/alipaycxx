
#pragma once

#include <string>
#include <functional>
#include <boost/system/error_code.hpp>
#include <boost/asio.hpp>
#include "json/json.h"
#include <avhttp.hpp>

class alipayclient
{
public:

	typedef std::map<std::string, std::string> stringmap;

	alipayclient(boost::asio::io_service& io, const std::string& appid, const std::string& pkey, const std::string& alipay_callback_url = std::string());
	~alipayclient();

	typedef std::function<void(boost::system::error_code ec, std::string response)> alipayinvok_handler;

	void async_invoke(const std::string& method, const Json::Value& param, alipayclient::alipayinvok_handler handler);

public:
	static std::string map_to_content(const alipayclient::stringmap& contentmap);
	static bool rsaVerify(const std::string &content, const std::string &sign, const std::string &key);
	static std::string aliPubKey;
private:
	void handle_request_return(boost::system::error_code ec, std::size_t bytes_transfered);


private:
	std::string appId;
	std::string privateKey;
	std::string alipay_callback_url;
	boost::asio::io_service& io;
};
