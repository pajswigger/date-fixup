package burp

import java.time.ZoneOffset
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter.RFC_1123_DATE_TIME


class BurpExtender: IBurpExtender {
    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks) {
        callbacks.setExtensionName("Date Fixer")
        callbacks.registerHttpListener(HttpListener(callbacks))
    }
}


class HttpListener(val callbacks: IBurpExtenderCallbacks): IHttpListener {
    override fun processHttpMessage(toolFlag: Int, messageIsRequest: Boolean, messageInfo: IHttpRequestResponse) {
        if(messageIsRequest) {
            return
        }

        val responseInfo = callbacks.helpers.analyzeResponse(messageInfo.response)
        val headers = responseInfo.headers.toMutableList()
        for(i in headers.indices) {
            if(headers[i].startsWith("Date:")) {
                headers[i] = "Date: " + RFC_1123_DATE_TIME.format(ZonedDateTime.now(ZoneOffset.UTC))
            }
        }

        val body = messageInfo.response.copyOfRange(responseInfo.bodyOffset, messageInfo.response.size)
        messageInfo.response = callbacks.helpers.buildHttpMessage(headers, body)
    }
}
