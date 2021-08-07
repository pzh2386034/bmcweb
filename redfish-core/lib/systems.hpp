/*
// Copyright (c) 2018 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/
#pragma once


#include "health.hpp"
#include "led.hpp"
#include "pcie.hpp"
#include "redfish_util.hpp"

#include <boost/container/flat_map.hpp>
#include <node.hpp>
#include <utils/fw_utils.hpp>
#include <utils/json_utils.hpp>

#include <variant>

#include <curl/curl.h>
#include "zdb.h"
#include <ctime>
#include <uuid/uuid.h>
#include <openssl/md5.h>

namespace redfish
{
/**
 * Systems derived class for delivering Computer Systems Schema.
 */
    static size_t writeFunction(void* ptr, size_t size, size_t nmemb, std::string* data) {
        data->append( static_cast<char*>(ptr), size * nmemb);
        return size * nmemb;
    }
class Systems : public Node
{
  public:
    /*
     * Default Constructor
     */
    Systems(App& app) : Node(app, "/open/bankcard/card-auth-detail")
    {
        entityPrivileges = {
            {boost::beast::http::verb::get, {{"Login"}}},
            {boost::beast::http::verb::head, {{"Login"}}},
            {boost::beast::http::verb::patch, {{"ConfigureComponents"}}},
            {boost::beast::http::verb::put, {{"ConfigureComponents"}}},
            {boost::beast::http::verb::delete_, {{"ConfigureComponents"}}},
            {boost::beast::http::verb::post, {{"ConfigureComponents"}}}};
    }

  private:
    /**
     * Functions triggers appropriate requests on DBus
     */
    void doGet(crow::Response& res, const crow::Request&,
               const std::vector<std::string>&) override
    {
        res.jsonValue["@odata.type"] = "#ComputerSystem.v1_12_0.ComputerSystem";
        res.jsonValue["Name"] = "Bank Card four essential factor";
        res.end();
    }


    void doPost(crow::Response& response, const crow::Request& req,
               const std::vector<std::string>&) override
    {
        std::optional<std::string> appId = "ZfI9MbUc";
        std::optional<std::string> appKey = "kC76TpKC";
        std::string name;
        std::string idNum;
        std::string cardNo;
        std::string mobile;

        if (!json_util::readJson(
                req, response, "appId", appId,"appKey", appKey, "name",
                name, "idNum", idNum, "cardNo",cardNo, "mobile", mobile))
        {
            return;
        }

        CURL *hnd;
        curl_mime *mime1;
        curl_mimepart *part1;

        mime1 = NULL;

        hnd = curl_easy_init();
        curl_easy_setopt(hnd, CURLOPT_BUFFERSIZE, 102400L);
        curl_easy_setopt(hnd, CURLOPT_URL, "https://api.253.com/open/bankcard/card-auth-detail");
        curl_easy_setopt(hnd, CURLOPT_NOPROGRESS, 1L);

        std::string response_string;
        std::string header_string;

        mime1 = curl_mime_init(hnd);
        part1 = curl_mime_addpart(mime1);
        curl_mime_data(part1, (*appId).c_str(), CURL_ZERO_TERMINATED);
        curl_mime_name(part1, "appId");
        part1 = curl_mime_addpart(mime1);
        curl_mime_data(part1, (*appKey).c_str(), CURL_ZERO_TERMINATED);
        curl_mime_name(part1, "appKey");
        part1 = curl_mime_addpart(mime1);
        curl_mime_data(part1, name.c_str(), CURL_ZERO_TERMINATED);
        curl_mime_name(part1, "name");
        part1 = curl_mime_addpart(mime1);
        curl_mime_data(part1, idNum.c_str(), CURL_ZERO_TERMINATED);
        curl_mime_name(part1, "idNum");
        part1 = curl_mime_addpart(mime1);
        curl_mime_data(part1, cardNo.c_str(), CURL_ZERO_TERMINATED);
        curl_mime_name(part1, "cardNo");
        part1 = curl_mime_addpart(mime1);
        curl_mime_data(part1, mobile.c_str(), CURL_ZERO_TERMINATED);
        curl_mime_name(part1, "mobile");
        curl_easy_setopt(hnd, CURLOPT_MIMEPOST, mime1);
        //curl_easy_setopt(hnd, CURLOPT_USERAGENT, "curl/7.58.0");
        curl_easy_setopt(hnd, CURLOPT_MAXREDIRS, 50L);
        //curl_easy_setopt(hnd, CURLOPT_VERBOSE, 1L);
        curl_easy_setopt(hnd, CURLOPT_FTP_SKIP_PASV_IP, 1L);
        curl_easy_setopt(hnd, CURLOPT_TCP_KEEPALIVE, 1L);

        curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, writeFunction);
        curl_easy_setopt(hnd, CURLOPT_WRITEDATA, &response_string);
        curl_easy_setopt(hnd, CURLOPT_HEADERDATA, &header_string);

        curl_easy_perform(hnd);

        curl_easy_cleanup(hnd);
        hnd = NULL;
        curl_mime_free(mime1);
        mime1 = NULL;
        curl_global_cleanup();

        response.jsonValue = nlohmann::json::parse(response_string);

        std::cout<<"chargeStatus: "<<response.jsonValue["chargeStatus"] <<std::endl;

        if (response.jsonValue["chargeStatus"] == 1)
        {
            //std::cout<<" begin to insert db:"<< "name:"<<name<<" idNum:"<<idNum<<"  cardNo:"<<cardNo<<"  mobile:"<<mobile <<std::endl;
            zdb::Connection conn = crow::dbconnections::dbpoll->getConnection();
            zdb::PreparedStatement p1 = conn.prepareStatement("insert into runoob_tbl (name, idNum, cardNo, mobile) values(?, ?, ?, ?);");
            conn.beginTransaction();
            p1.bind(1, name);
            p1.bind(2, idNum);
            p1.bind(3, cardNo); // include terminating \0
            p1.bind(4, mobile);
            p1.execute();
            conn.commit();
        }
        else if(response.jsonValue["chargeStatus"] == 0)
        {
            std::cout<<" charge failed."<<std::endl;
        }

        response.end();
    }


};

/**
 * SystemResetActionInfo derived class for delivering Computer Systems
 * ResetType AllowableValues using ResetInfo schema.
 */
class SystemResetActionInfo : public Node
{
  public:
    /*
     * Default Constructor
     */
    SystemResetActionInfo(App& app) :
        Node(app, "/api/nsc/openapi/multipleLoans")
    {
        entityPrivileges = {
            {boost::beast::http::verb::get, {{"Login"}}},
            {boost::beast::http::verb::head, {{"Login"}}},
            {boost::beast::http::verb::patch, {{"ConfigureComponents"}}},
            {boost::beast::http::verb::put, {{"ConfigureComponents"}}},
            {boost::beast::http::verb::delete_, {{"ConfigureComponents"}}},
            {boost::beast::http::verb::post, {{"ConfigureComponents"}}}};
    }

  private:
    /**
     * Functions triggers appropriate requests on DBus
     */
    void doGet(crow::Response& res, const crow::Request&,
               const std::vector<std::string>&) override
    {
        res.jsonValue["@odata.type"] = "#ComputerSystem.v1_12_0.ComputerSystem";
        res.jsonValue["Name"] = "Anti-Fraud Product";
        res.end();
    }
    static std::string getUrl(std::string carNo, std::string mobile, std::string name, std::string userIp)
    {
        std::string reqUrl("https://antielectricfraud-prod-api.qunlicloud.com/api/nsc/openapi/multipleLoans?");
        reqUrl += "phoneNumber=";
        reqUrl += mobile;
        reqUrl += "&";
        reqUrl += "idNumber=";
        reqUrl += carNo;
        if (name != "")
        {
            reqUrl += "&name=";
            reqUrl += name;
        }
        if (userIp != "")
        {
            reqUrl += "&userIp=";
            reqUrl += userIp;
        }
        BMCWEB_LOG_DEBUG<<"product A, getUrl:"<<reqUrl;
        return reqUrl;
    }
    static struct curl_slist * getHeaderList()
    {
        struct curl_slist *chunk = NULL;
        std::time_t t = std::time(0);
        std::string t_string = std::to_string(t);
        uuid_t  nonce;
        uuid_generate_random(nonce);
        //std::string nonceStr(nonce);
        std::stringstream nonceBuf;
        for (size_t i = 0; i < sizeof (nonce); i++)
            nonceBuf << std::hex<<static_cast<int>(nonce[i]);
        std::string clientId("172409b6-f7df-11ea-be6e-fa163efee3db");

        std::string hdrTimeStamp("Ql-Auth-Timestamp: ");
        std::string hdrNonce("Ql-Auth-Nonce: ");
        std::string hdrSign("Ql-Auth-Sign: ");
        std::string hdrClientId("Ql-Auth-clientId: ");
        /* calculate MD5 stage one : MD5(nonce+timestamp) */
        unsigned char md1[16];
        unsigned char md2[16];
        std::stringstream md5input;

        md5input<<nonceBuf.str()<<t_string;
        BMCWEB_LOG_ERROR<<"first stage md5input:"<<md5input.str();

        MD5(reinterpret_cast<const unsigned char *>(md5input.str().c_str()), md5input.str().length(), md1);

        std::stringstream md1Buf;
        for (size_t i = 0; i< sizeof(md1); i++)
        {
            md1Buf<<std::hex<<std::setfill('0')<< std::setw(2)<<static_cast<int>(md1[i]);
        }
        BMCWEB_LOG_ERROR<<"md5 first stage:"<<md1Buf.str();

        /* calculate MD5 stage two : MD5(MD5(nonce+timestamp)+clientId) */
        md5input.str("");
        md5input<<md1Buf.str()<<clientId.c_str();
        BMCWEB_LOG_ERROR<<"second stage md5input:"<<md5input.str();

        MD5(reinterpret_cast<const unsigned char *>(md5input.str().c_str()),  md5input.str().length(), md2);
        std::stringstream md5Resultbuf;
        for (size_t i = 0; i < sizeof(md2); i++)
            md5Resultbuf << std::hex<<std::setfill('0')<< std::setw(2)<<static_cast<int>(md2[i]);

        hdrTimeStamp += std::to_string(t);
        hdrNonce += nonceBuf.str();
        hdrSign += md5Resultbuf.str();
        hdrClientId += clientId;

        chunk = curl_slist_append(chunk, hdrTimeStamp.c_str());

        chunk = curl_slist_append(chunk, hdrNonce.c_str());

        chunk = curl_slist_append(chunk, hdrSign.c_str());

        chunk = curl_slist_append(chunk, hdrClientId.c_str());

        return chunk;
    }
    void doPost(crow::Response& response, const crow::Request& req,
               const std::vector<std::string>&) override
    {
        std::string idNum;
        std::string mobile;
        std::optional<std::string> name("");
        std::string nameEncode("");
        std::optional<std::string> userIp("");
        if (!json_util::readJson(
                req, response, "idNum",idNum, "mobile", mobile, "name", name, "userIp", userIp))
        {
            return;
        }
        CURL *curl;
        char *output = NULL;

        curl = curl_easy_init();
        if(name && curl) {
            output = curl_easy_escape(curl, name->c_str(), static_cast<int>(name->length()) );
            if(output) {
                nameEncode += output;
                curl_free(output);
            }
        }
        std::string reqUrl = getUrl(idNum, mobile, nameEncode, *userIp);
        std::string response_string;
        std::string header_string;



        if(curl) {
            struct curl_slist *chunk = getHeaderList();

            /* set our custom set of headers */
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);

            curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
            //curl_easy_setopt(hnd, CURLOPT_BUFFERSIZE, 1024L);
            curl_easy_setopt(curl, CURLOPT_URL, reqUrl.c_str());
            curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);

            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeFunction);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_string);
            curl_easy_setopt(curl, CURLOPT_HEADERDATA, &header_string);

            curl_easy_perform(curl);

            curl_easy_cleanup(curl);
            curl = NULL;
            curl_slist_free_all(chunk);
            curl_global_cleanup();

            response.jsonValue = nlohmann::json::parse(response_string);

            std::cout<<"code: "<<response.jsonValue["code"] <<std::endl;

            if (response.jsonValue["code"] == "10000")
            {
                std::cout<<" begin to insert db for product A:"<<"  idNum:"<<idNum<<"  mobile:"<<mobile <<std::endl;
/*                 zdb::Connection conn = crow::dbconnections::dbpoll->getConnection();
                zdb::PreparedStatement p1 = conn.prepareStatement("insert into runoob_tbl (name, idNum, cardNo, mobile) values(?, ?, ?, ?);");
                conn.beginTransaction();
                p1.bind(1, name);
                p1.bind(2, idNum);
                p1.bind(3, cardNo); // include terminating \0
                p1.bind(4, mobile);
                p1.execute();
                conn.commit(); */
            }
            else
            {
                std::cout<<" query failed:"<<response.jsonValue["code"]<<std::endl;
                std::cout<<response.jsonValue.dump()<<std::endl;
            }
            response.end();

        }
        else
        {
            messages::serviceInUnknownState(response);
            return;
        }
    }

};
} // namespace redfish
