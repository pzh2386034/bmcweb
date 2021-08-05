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
            reqUrl += "&name:";
            reqUrl += name;
        }
        if (userIp != "")
        {
            reqUrl += "&userIp:";
            reqUrl += userIp;
        }
        BMCWEB_LOG_DEBUG<<"product A, getUrl:"<<reqUrl;
        return reqUrl;
    }
    static struct curl_slist * getHeaderList(std::string)
    {
        struct curl_slist *chunk = NULL;
        std::time_t t = std::time(0);
        uuid_t  nonce;
        uuid_generate_random(&nonce);
        std::string nonceStr(nonce);
        std::string clientId("172409b6-f7df-11ea-be6e-fa163efee3db");

        std::string hdrTimeStamp("Ql-Auth-Timestamp: ");
        std::string hdrNonce("Ql-Auth-Nonce: ");
        std::string hdrSign("Ql-Auth-Sign: ");
        std::string hdrClientId("Ql-Auth-clientId: ");
        /* calculate MD5 stage one : MD5(nonce+timestamp) */
        unsigned char md1[16];
        unsigned char md2[16];
        unsigned char md5input[100];
        memset(md5input, 0, sizeof(md5input));
        memcpy(md5input, nonce, sizeof(uuid_t));
        memcpy(md5input + sizeof(uuid_t), &t, sizeof(std::time_t));

        MD5(md5input, sizeof(uuid_t) + sizeof(std::time_t), md1);
        /* calculate MD5 stage two : MD5(MD5(nonce+timestamp)+clientId) */
        memset(md5input, 0, sizeof(md5input));
        memcpy(md5input, md1, sizeof(md1));
        strcpy(md5input, clientId.c_str());

        MD5(md5input, sizeof(md1) + clientId.length(), md2);
        //std::string sign(md2);

        hdrTimeStamp += std::to_string(t);
        hdrNonce += nonceStr;
        hdrSign.append(sign);
        hdrClientId += clientId;

        //chunk = curl_slist_append(chunk, "Accept:");

        chunk = curl_slist_append(chunk, hdrTimeStamp.c_str());

        chunk = curl_slist_append(chunk, hdrNonce.c_str());

        chunk = curl_slist_append(chunk, hdrSign.c_str());

        chunk = curl_slist_append(chunk, hdrClientId.c_str());

        return chunk;
    }
    void doPost(crow::Response& response, const crow::Request& req,
               const std::vector<std::string>&) override
    {
        std::string cardNo;
        std::string mobile;
        std::optional<std::string> name("");
        std::optional<std::string> userIp("");
        if (!json_util::readJson(
                req, response, "cardNo",cardNo, "mobile", mobile, "name", name, "userIp", userIp))
        {
            return;
        }

        std::string reqUrl = getUrl(cardNo, mobile, *name, *userIp);
        std::string response_string;
        std::string header_string;


        //BMCWEB_LOG_DEBUG << "timestamp:"<<t;
/*         for (i = 0; i < 16; i++){
            sprintf(tmp,"%2.2x",md[i]);
            strcat(buf,tmp);
        }
        printf("%s/n",buf); */


        CURL *curl;

        curl = curl_easy_init();
        if(curl) {
            struct curl_slist *chunk = getHeaderList();

/*             chunk = curl_slist_append(chunk, "Accept:");
            chunk = curl_slist_append(chunk, hdrTimeStamp.c_str());
            chunk = curl_slist_append(chunk, hdrNonce.c_str());
            chunk = curl_slist_append(chunk, hdrSign.c_str());

            chunk = curl_slist_append(chunk, hdrClientId.c_str()); */

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
                std::cout<<" begin to insert db for product A:"<<"  cardNo:"<<cardNo<<"  mobile:"<<mobile <<std::endl;
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
