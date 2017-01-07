
#include <systemd/sd-journal.h>

#include "openssl/pem.h"
#include "openssl/rsa.h"
#include "openssl/x509.h"
#include "openssl/sha.h"

#include "json/json.h"
#include <avhttp.hpp>
#include "alipayclient.hpp"
#include "escape_string.hpp"

#ifndef XRSA_KEY_BITS
#define XRSA_KEY_BITS (1024)
#endif


typedef std::map<std::string, std::string> stringmap;

static const std::string default_charset      = "utf-8";
static const std::string default_url          = "https://openapi.alipay.com/gateway.do";
static const std::string default_sign_type    = "RSA";
static const std::string default_version      = "2.0";

static const std::string KEY_APP_ID           = "app_id";
static const std::string KEY_METHOD           = "method";
static const std::string KEY_CHARSET          = "charset";
static const std::string KEY_SIGN_TYPE        = "sign_type";
static const std::string KEY_SIGN             = "sign";
static const std::string KEY_TIMESTAMP        = "timestamp";
static const std::string KEY_VERSION          = "version";
static const std::string KEY_BIZ_CONTENT      = "biz_content";

/** 支付宝公钥，用来验证支付宝返回请求的合法性 **/
std::string alipayclient::aliPubKey = "-----BEGIN PUBLIC KEY-----\n"
        "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDDI6d306Q8fIfCOaTXyiUeJHkr\n"
        "IvYISRcc73s3vF1ZT7XN8RNPwJxo8pWaJMmvyTn9N4HQ632qJBVHf8sxHi/fEsra\n"
        "prwCtzvzQETrNRwVxLO5jVmRGi60j8Ue1efIlzPXV9je9mkjzOmdssymZkh2QhUr\n"
        "CmZYI/FCEa3/cNMW0QIDAQAB\n"
        "-----END PUBLIC KEY-----";

static bool base64Decode(const std::string &str, unsigned char *bytes, int &len)
{
	const char *cstr = str.c_str();
	BIO *bmem = NULL;
	BIO *b64 = NULL;

	b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	bmem = BIO_new_mem_buf((void *)cstr, strlen(cstr));
	b64 = BIO_push(b64, bmem);
	len = BIO_read(b64, bytes, len);

	BIO_free_all(b64);
	return len > 0;
}

std::string base64Encode(const unsigned char *bytes, int len)
{
	BIO *bmem = NULL;
	BIO *b64 = NULL;
	BUF_MEM *bptr = NULL;

	b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	bmem = BIO_new(BIO_s_mem());
	b64 = BIO_push(b64, bmem);
	BIO_write(b64, bytes, len);
	BIO_flush(b64);
	BIO_get_mem_ptr(b64, &bptr);

	std::string str = std::string(bptr->data, bptr->length);
	BIO_free_all(b64);
	return str;
}

static std::string rsaSign(const std::string &content, const std::string &key)
{
	std::string signed_str;
	const char *key_cstr = key.c_str();
	int key_len = std::strlen(key_cstr);
	BIO *p_key_bio = BIO_new_mem_buf((void *)key_cstr, key_len);
	RSA *p_rsa = PEM_read_bio_RSAPrivateKey(p_key_bio, NULL, NULL, NULL);

	if (p_rsa != NULL) {

		const char *cstr = content.c_str();
		unsigned char hash[SHA_DIGEST_LENGTH] = {0};
		SHA1((unsigned char *)cstr, strlen(cstr), hash);
		//unsigned char sign[XRSA_KEY_BITS / 8] = {0};
		std::string sign;
		sign.resize(XRSA_KEY_BITS / 8);
		unsigned int sign_len = sign.length();
		int r = RSA_sign(NID_sha1, hash, SHA_DIGEST_LENGTH, (unsigned char*)sign.data(), &sign_len, p_rsa);

		if (0 != r && sign.length() == sign_len) {
			sign.resize(sign_len);
			signed_str = base64Encode((unsigned char*)sign.data(), sign_len);
		}
	}

	RSA_free(p_rsa);
	BIO_free(p_key_bio);
	return signed_str;
}

bool alipayclient::rsaVerify(const std::string &content, const std::string &sign, const std::string &key)
{
	bool result = false;
	const char *key_cstr = key.c_str();
	int key_len = strlen(key_cstr);
	BIO *p_key_bio = BIO_new_mem_buf((void *)key_cstr, key_len);
	RSA *p_rsa = PEM_read_bio_RSA_PUBKEY(p_key_bio, NULL, NULL, NULL);

	if (p_rsa != NULL) {
		const char *cstr = content.c_str();
		unsigned char hash[SHA_DIGEST_LENGTH] = {0};
		SHA1((unsigned char *)cstr, strlen(cstr), hash);
		unsigned char sign_cstr[XRSA_KEY_BITS / 8] = {0};
		int len = XRSA_KEY_BITS / 8;
		base64Decode(sign, sign_cstr, len);
		unsigned int sign_len = XRSA_KEY_BITS / 8;
		int r = RSA_verify(NID_sha1, hash, SHA_DIGEST_LENGTH, (unsigned char *)sign_cstr, sign_len, p_rsa);

		if (r > 0) {
			result = true;
		}
	}

	RSA_free(p_rsa);
	BIO_free(p_key_bio);
	return result;
}

alipayclient::alipayclient(boost::asio::io_service& io, const std::string& appid, const std::string& pkey, const std::string& callback_url)
	: io(io)
	, appId(appid)
	, privateKey(pkey)
	, alipay_callback_url(callback_url)
{
}

alipayclient::~alipayclient()
{
}

void alipayclient::async_invoke(const std::string& method, const Json::Value& param, alipayclient::alipayinvok_handler handler)
{
	alipayclient::stringmap extented;

	if (method == "alipay.trade.precreate")
	{
		extented.insert(alipayclient::stringmap::value_type("notify_url", alipay_callback_url));
	}

	std::time_t t = std::time(0);
	char tmp[64];
	std::strftime(tmp, sizeof(tmp), "%Y-%m-%d %X", std::localtime(&t));

	std::string content;

	Json::FastWriter fwriter;
	fwriter.omitEndingLineFeed();

	content = fwriter.write(param);

	stringmap requestPairs;
	requestPairs.insert(stringmap::value_type(KEY_APP_ID, appId));
	requestPairs.insert(stringmap::value_type(KEY_BIZ_CONTENT, content));
	requestPairs.insert(stringmap::value_type(KEY_CHARSET, "utf-8"));
	requestPairs.insert(stringmap::value_type(KEY_METHOD, method));
	requestPairs.insert(stringmap::value_type(KEY_SIGN_TYPE, default_sign_type));
	requestPairs.insert(stringmap::value_type(KEY_TIMESTAMP, tmp));
	requestPairs.insert(stringmap::value_type(KEY_VERSION, default_version));

	/** 追加外部传入的网关的补充参数，如notify_url等 **/
	for (const auto & i : extented)
	{
		requestPairs.insert(i);
	}

	std::string wholeContent = map_to_content(requestPairs);
	std::string sign = rsaSign(wholeContent, privateKey);
	requestPairs.insert(stringmap::value_type(KEY_SIGN, sign));

    std::string requestEntity;
	for (const stringmap::value_type& v : requestPairs)
	{
		std::string item = string_util::escape_path(v.first);
		item += "=";
		auto encodedValue = string_util::escape_path(v.second);
		item += string_util::escape_path(v.second);;

		if (!requestEntity.empty()) {
			requestEntity.push_back('&');
		}
		requestEntity.append(item);
		item.clear();
	}


	auto m_http_stream = std::make_shared<avhttp::http_stream>(io);
	auto m_readbuf = std::make_shared<boost::asio::streambuf>();

	avhttp::request_opts opt;

	opt(avhttp::http_options::request_method, "POST")
		(avhttp::http_options::request_body, requestEntity)
		(avhttp::http_options::content_length, boost::lexical_cast<std::string>(requestEntity.length()))
		(avhttp::http_options::content_type, "application/x-www-form-urlencoded; charset=utf-8")
	;

	m_http_stream->request_options(opt);

	if (boost::filesystem::exists("/etc/ssl/certs/ca-bundle.crt"))
		m_http_stream->load_verify_file("/etc/ssl/certs/ca-bundle.crt");
	else
		m_http_stream->add_verify_path("/etc/ssl/certs");
	m_http_stream->check_certificate(true);

	avhttp::async_read_body(*m_http_stream, default_url, *m_readbuf, [this, m_readbuf, m_http_stream, handler](boost::system::error_code ec, std::size_t bytes_transfered)
	{
		if (ec || bytes_transfered <=0)
		{
			handler(ec, "");
			return;
		}

		// decode the returned data
		std::string responseStr;
		responseStr.resize(bytes_transfered);

		m_readbuf->sgetn(&responseStr[0], bytes_transfered);

		std::stringstream ss;
		ss.str(responseStr);
		Json::Value responseObj;

		std::cerr << responseStr << std::endl;

		try{
		ss >> responseObj;
		}catch(...){
			handler(boost::system::errc::make_error_code(boost::system::errc::protocol_error), "");
			return;
		};

		//获取返回报文中的alipay_xxx_xxx_response的内容;
		int beg = responseStr.find("_response\"");
		int end = responseStr.rfind("\"sign\"");
		if (beg < 0 || end < 0) {
			handler(boost::system::errc::make_error_code(boost::system::errc::protocol_error), std::string());
			return;
		}
		beg = responseStr.find('{', beg);
		end = responseStr.rfind('}', end);
		//注意此处将map转为json之后的结果需要与支付宝返回报文中原格式与排序一致;
		//排序规则是节点中的各个json节点key首字母做字典排序;
		//Response的Json值内容需要包含首尾的“{”和“}”两个尖括号，双引号也需要参与验签;
		//如果字符串中包含“http://”的正斜杠，需要先将正斜杠做转义，默认打印出来的字符串是已经做过转义的;
		//此处转换之后的json字符串默认为"Compact"模式，即紧凑模式，不要有空格与换行;
		std::string responseContent = responseStr.substr(beg, end - beg + 1);

	//   DebugLog("ResponseContent:%s", responseContent.c_str());

		//此处为校验支付宝返回报文中的签名;
		//如果支付宝公钥为空，则默认跳过该步骤，不校验签名;
		//如果支付宝公钥不为空，则认为需要校验签名;

		//获取返回报文中的sign;
		std::string responseSign = responseObj[KEY_SIGN].asString();

		//调用验签方法;
		bool verifyResult = rsaVerify(responseContent, responseSign, aliPubKey);

		if (!verifyResult) {
			handler(boost::system::errc::make_error_code(boost::system::errc::protocol_error), std::string());
			return;
		}

		handler(boost::system::error_code(), responseContent);
	});
}

std::string alipayclient::map_to_content(const alipayclient::stringmap& contentmap)
{
	std::string content;
	for (const auto & p : contentmap)
	{
		if (!content.empty()) {
			content.push_back('&');
		}
		content.append(p.first);
		content.push_back('=');
		content.append(p.second);
	}
	return content;
}


