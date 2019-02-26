#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <limits>
#include <locale>
#include <random>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>

#include <openssl/hmac.h>

namespace
{

bool is_whitelist_character_of_percent_encoding(char v)
{
  if (std::isalpha(v) || std::isdigit(v)) {
    return true;
  }
  switch (v) {
  case '-':
  case '.':
  case '_':
  case '~':
    return true;
  }
  return false;
}

std::string encode_percent_encoding(std::string_view sv)
{
  std::stringstream ss{};
  ss << std::hex << std::uppercase << std::setfill('0');
  for (unsigned char v : sv) {
    if (is_whitelist_character_of_percent_encoding(v)) {
      ss.put(v);
    } else {
      ss.put('%');
      ss << std::setw(2) << static_cast<int>(v);
    }
  }
  return ss.str();
}

template<typename T>
std::string get_authorizing_oauth_value(T begin, T end)
{
  std::sort(begin, end);
  std::string result{"OAuth "};
  bool is_first {true};
  for (auto it{begin}; it != end; ++it) {
    if (!std::exchange(is_first, false)) {
      result.append(", ");
    }
    result.append(encode_percent_encoding(it->first)).append("=\"").append(encode_percent_encoding(it->second).append(1, '"'));
  }
  return result;
}

std::string hash_hmac_sha1(const std::string& key, const std::string& data)
{
  char result[21]{'\0'};
  unsigned int read_count;
  HMAC(EVP_sha1(), key.data(), key.size(), reinterpret_cast<const unsigned char*>(data.data()), data.size(), reinterpret_cast<unsigned char*>(result), &read_count);
  return {result};
}

std::string encode64(std::string_view val)
{
  using namespace boost::archive::iterators;
  using It = base64_from_binary<transform_width<std::string::const_iterator, 6, 8>>;
  auto tmp = std::string(It(std::begin(val)), It(std::end(val)));
  return tmp.append((3 - val.size() % 3) % 3, '=');
}

template<typename T>
std::string encode_url(T begin, T end)
{
  std::vector<std::pair<std::string, std::string>> encorded{};
  for (auto it{begin}; it != end; ++it) {
    encorded.emplace_back(encode_percent_encoding(it->first), encode_percent_encoding(it->second));
  }
  std::string result;
  bool is_first {true};
  for (const auto& v : encorded) {
    if (!std::exchange(is_first, false)) {
      result.append(1, '&');
    }
    result.append(v.first).append(1, '=').append(v.second);
  }
  return result;
}

template<typename T>
std::string signature_oauth_hmac_sha1(std::string_view key, const boost::beast::http::request<boost::beast::http::string_body>& req, T begin, T end)
{
  std::vector<std::pair<std::string, std::string>> encorded{};
  for (auto it{begin}; it != end; ++it) {
    encorded.emplace_back(encode_percent_encoding(it->first), encode_percent_encoding(it->second));
  }
  std::sort(encorded.begin(), encorded.end());
  std::string concatenated {};
  bool is_first {true};
  for (const auto& v : encorded) {
    if (!std::exchange(is_first, false)) {
      concatenated.append(1, '&');
    }
    concatenated.append(v.first).append(1, '=').append(v.second);
  }

  std::string result {req.method_string()};
  const auto host{req.at(boost::beast::http::field::host)};
  const auto target{req.target()};
  result.append("&https").append(encode_percent_encoding("://")).append(encode_percent_encoding(std::string{host})).append(encode_percent_encoding(std::string{target})).append(1, '&').append(encode_percent_encoding(concatenated));
  const auto sha1_hash {hash_hmac_sha1({key.begin(), key.end()}, result)};
  return encode64(sha1_hash);
}

template<typename T>
T get_value(std::istream& is)
{
  T v;
  is >> v;
  return v;
}

std::string get_string_to_eof(std::istream& is)
{
  return {std::istreambuf_iterator<char>{is}, std::istreambuf_iterator<char>{}};
}

}

int main(int argc, char** argv)
{
  constexpr auto host{"api.twitter.com"};
  constexpr auto method{"https"};
  constexpr auto target{"/1.1/statuses/update.json"};
  constexpr auto version{11};
  const std::vector<std::pair<std::string, std::string>> oauth_parameters_template {
    {"oauth_consumer_key", argv[1]},
    {"oauth_nonce", ""},
    {"oauth_signature_method", "HMAC-SHA1"},
    {"oauth_timestamp", ""},
    {"oauth_token", argv[2]},
    {"oauth_version", "1.0"}
  };

  if (argc < 3) {
    std::cout << "This application need 2 arguments:\nex) " << *argv << " [API key] [Access token secret]\n";
    return EXIT_SUCCESS;
  }

  try {
    const auto api_secret_key {get_value<std::string>(std::cin)};
    const auto api_secret_key_encorded {encode_percent_encoding(api_secret_key)};
    const auto access_token_secret {get_value<std::string>(std::cin)};
    const auto access_token_secret_encorded {encode_percent_encoding(access_token_secret)};
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    const std::vector<std::pair<std::string, std::string>> body_parameters {
      {"status", get_string_to_eof(std::cin)}
    };

    boost::asio::io_context ioc{};
    boost::asio::ssl::context ctx{boost::asio::ssl::context::tlsv12_client};
    ctx.set_default_verify_paths();
    boost::asio::ssl::stream<boost::asio::ip::tcp::socket> stream{ioc, ctx};

    boost::beast::http::request<boost::beast::http::string_body> req{boost::beast::http::verb::post, target, version};
    req.set(boost::beast::http::field::host, host);
    req.set(boost::beast::http::field::user_agent, BOOST_BEAST_VERSION_STRING);
    req.set(boost::beast::http::field::content_type, "application/x-www-form-urlencoded");
    req.body() = encode_url(body_parameters.begin(), body_parameters.end());
    req.content_length(req.body().size());

    auto oauth_parameters {oauth_parameters_template};
    const auto find_value_by_first{[](const auto& value){return [value](const auto& v){return v.first == value;};}};
    std::find_if(oauth_parameters.begin(), oauth_parameters.end(), find_value_by_first("oauth_nonce"))->second = std::to_string(std::random_device{}());
    std::find_if(oauth_parameters.begin(), oauth_parameters.end(), find_value_by_first("oauth_timestamp"))->second = std::to_string(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());

    auto signature_parameters {oauth_parameters};
    signature_parameters.insert(signature_parameters.end(), body_parameters.begin(), body_parameters.end());
    const auto signature {signature_oauth_hmac_sha1(api_secret_key + '&' + access_token_secret, req, signature_parameters.begin(), signature_parameters.end())};
    oauth_parameters.emplace_back("oauth_signature", signature);
    req.set("Authorization", get_authorizing_oauth_value(oauth_parameters.begin(), oauth_parameters.end()));

    std::cout << req << "\n\n";

    boost::asio::connect(stream.next_layer(), boost::asio::ip::tcp::resolver{ioc}.resolve(host, method));
    stream.handshake(boost::asio::ssl::stream_base::client);

    boost::beast::http::write(stream, req);

    boost::beast::flat_buffer buffer;
    boost::beast::http::response<boost::beast::http::dynamic_body> res;
    boost::beast::http::read(stream, buffer, res);

    std::cout << res << std::endl;

    boost::system::error_code ec;
    stream.shutdown(ec);
    if(ec && ec != boost::asio::error::eof)
      throw boost::system::system_error{ec};
  } catch(const std::exception& e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}
