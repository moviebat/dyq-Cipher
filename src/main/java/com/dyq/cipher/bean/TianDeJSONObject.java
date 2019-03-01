package com.dyq.cipher.bean;

import java.util.Iterator;
import java.util.Map;

import com.alibaba.fastjson.JSONObject;
/**
 * 重写toJSONString()
 * @author xiaoming
 * 2017年5月18日
 */
public class TianDeJSONObject extends JSONObject{
    public TianDeJSONObject(){}
    
    public TianDeJSONObject(Map map){
    	super(map);
    }
    
	@Override
	public String toJSONString() {
		StringBuilder sb = new StringBuilder();
		sb.append("{");
		
		Iterator<String> keyI = this.keySet().iterator();
		while(keyI.hasNext()){
			String key = keyI.next();
			String value = this.getString(key);
			
			/* 简单组装jsonObject */
			sb.append("\"" + key + "\":");
			sb.append("\"" + value + "\",");
		}
		sb.replace(sb.length() - 1, sb.length(), "}");
		
		return sb.toString();
	}
	
}
