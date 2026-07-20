package com.vuln.fastjson;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.ParserConfig;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.Map;

@Controller
public class ParseController {

    @GetMapping(value = "/", produces = MediaType.TEXT_HTML_VALUE)
    @ResponseBody
    public String index() {
        String cl = String.valueOf(ParserConfig.class.getClassLoader());
        boolean autoType = ParserConfig.getGlobalInstance().isAutoTypeSupport();
        return "<!DOCTYPE html><html><head><meta charset='utf-8'><title>Fastjson 1.2.83 RCE</title></head><body>"
            + "<h2>Fastjson 1.2.83 Vuln Environment</h2>"
            + "<p><b>ClassLoader:</b> " + cl.replace("<", "&lt;") + "</p>"
            + "<p><b>autoTypeSupport:</b> " + autoType + "</p>"
            + "<p><b>safeMode:</b> false</p>"
            + "<hr><h3>Test</h3>"
            + "<form id='f'>"
            + "<textarea id='payload' rows='5' cols='80'>{\"@type\":\"java.net.Inet4Address\",\"val\":\"example.com\"}</textarea><br><br>"
            + "<button type='submit'>Send to /parse</button>"
            + "</form>"
            + "<pre id='result'></pre>"
            + "<script>"
            + "document.getElementById('f').onsubmit=function(e){"
            + "e.preventDefault();"
            + "fetch('/parse',{method:'POST',headers:{'Content-Type':'application/json'},body:document.getElementById('payload').value})"
            + ".then(r=>r.text()).then(t=>{document.getElementById('result').textContent=t;});"
            + "};"
            + "</script>"
            + "</body></html>";
    }

    @GetMapping(value = "/info", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public Map<String, Object> info() {
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("parserConfigCL", String.valueOf(ParserConfig.class.getClassLoader()));
        r.put("autoTypeSupport", ParserConfig.getGlobalInstance().isAutoTypeSupport());
        r.put("safeMode", false);
        return r;
    }

    @PostMapping(value = "/parse", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public Map<String, Object> parse(@RequestBody String payload) {
        Map<String, Object> r = new LinkedHashMap<>();
        ClassLoader original = Thread.currentThread().getContextClassLoader();
        try {
            Thread.currentThread().setContextClassLoader(ParserConfig.class.getClassLoader());
            Object obj = JSON.parse(payload);
            r.put("ok", true);
            r.put("class", obj == null ? "null" : obj.getClass().getName());
            r.put("result", String.valueOf(obj));
        } catch (Throwable e) {
            r.put("ok", false);
            r.put("error", e.getClass().getName() + ": " + e.getMessage());
        } finally {
            Thread.currentThread().setContextClassLoader(original);
        }
        return r;
    }
}
