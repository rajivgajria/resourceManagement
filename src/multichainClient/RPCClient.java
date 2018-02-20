package multichainClient;

import java.io.IOException;
import java.util.UUID;

import org.apache.commons.codec.binary.Hex;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.ParseException;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

/**
 * This Class contains the methods to interact with the Blockchain
 * @author 
 *
 */
public class RPCClient{

    private static final String LIST_STREAMS = "liststreams";
    private static final String GET_INFO = "getinfo";
    private static final String GET_STREAM_KEY_ITEMS = "liststreamkeyitems";
    private static final String PUBLISH_ITEMS_FOR_KEY = "publish";
    private static final String LIST_ADDRESSES = "listaddresses";
    private static final String RPC_ADDRESS = "localhost";
    private static final int RPC_PORT = 2760;
    private static final String RPC_USERNAME = "multichainrpc";
    private static final String RPC_PASSWORD = "9kE4UQtdiwjQ4CFqitkhJpm1ZYGemXwUcxqwqFCH1Fb3";

    /**
     * This method Submits the JSON-RPC request to the Blockchain and returns the content received from the server. 
     * @param id
     * @param method
     * @param params
     * @return
     * @throws IOException
     */
    @SuppressWarnings("unchecked")
    public JSONObject invokeRPC(String id, String method, Object[] params) throws IOException{
	CloseableHttpClient httpclient = null;
	JSONObject json = new JSONObject();
	json.put("id", id);
	json.put("method", method);
	if (params != null){
	    JSONArray list = new JSONArray();
	    // Print the objects in a for-loop.
	    for (Object e : params){
		list.add(e);
	    }

	    json.put("params", list);

	}
	System.out.println(json);
	JSONObject responseJsonObj = null;
	try{
	    	CredentialsProvider credsProvider = new BasicCredentialsProvider();
		AuthScope authScope = new AuthScope(RPC_ADDRESS, RPC_PORT);
		UsernamePasswordCredentials userNamePassword = new UsernamePasswordCredentials(RPC_USERNAME, RPC_PASSWORD);
	        credsProvider.setCredentials(authScope,userNamePassword);
	        httpclient = HttpClients.custom().setDefaultCredentialsProvider(credsProvider).build();
	    
	        StringEntity myEntity = new StringEntity(json.toJSONString());
    	    	// System.out.println(json.toString());
	        String url = "http://"+RPC_ADDRESS+":"+RPC_PORT;
    	    	HttpPost httppost = new HttpPost(url);
    	    	httppost.setHeader("Accept", "application/json");
    	    	httppost.setHeader("Content-type", "application/json");

    	    	httppost.setEntity(myEntity);
    
    	    	// System.out.println("executing request" +
    	    	// httppost.getRequestLine());
    	    	HttpResponse response = httpclient.execute(httppost);
    	    	HttpEntity entity = response.getEntity();
    
    	    	// System.out.println("----------------------------------------");
    	    	// System.out.println(response.getStatusLine());
    	    	if (entity != null){
    	    	    System.out.println("Response content length: " + entity.getContentLength());
    	    	}
    	    	JSONParser parser = new JSONParser();
    	    	responseJsonObj = (JSONObject) parser.parse(EntityUtils.toString(entity));
    		} catch (ClientProtocolException e){
    		    e.printStackTrace();
    		} catch (IOException e){
    		    e.printStackTrace();
    		} catch (ParseException e){
    		    e.printStackTrace();
    		} catch (org.json.simple.parser.ParseException e){
    		    e.printStackTrace();
    		} 
		finally{
    		    httpclient.close();;
		}
		return responseJsonObj;
    }

    public JSONObject getstreams(String chainName) throws IOException{
	JSONObject json = invokeRPC(UUID.randomUUID().toString(), LIST_STREAMS, null);
	return json;
    }

    public JSONObject getaddresses(String chainName) throws IOException{
	JSONObject json = invokeRPC(UUID.randomUUID().toString(), LIST_ADDRESSES, null);
	return json;
    }

    public JSONObject getInfo(String chainName) throws IOException{
	JSONObject json = invokeRPC(UUID.randomUUID().toString(), GET_INFO, null);
	return (JSONObject) json.get("result");
    }

    public JSONObject getStreamKeyItems(String streamName, String keyName) throws IOException{
	Object[] params = { streamName, keyName };
	JSONObject json = invokeRPC(UUID.randomUUID().toString(), GET_STREAM_KEY_ITEMS, params);
	return json;
    }

    public String getStreamKeyItemsData(String streamName, String keyName) throws IOException{
	String data = "";
	Object[] params = { streamName, keyName };
	JSONObject json = invokeRPC(UUID.randomUUID().toString(), GET_STREAM_KEY_ITEMS, params);
	JSONArray result = (JSONArray) json.get("result");
	for (Object o : result){
	    JSONObject jsonLineItem = (JSONObject) o;
	    data = jsonLineItem.get("data").toString();
	    System.out.println(data);
	}
	try{
	    if (data == null)
		return "error";
	    else
		return data;
	} catch (Exception e){
	    e.printStackTrace();
	    return "Error";
	}
    }

    /**
     * This method reads data that is stored against the keyName from the stream streamName and returns it. 
     * @param streamName
     * @param keyName
     * @return
     * @throws IOException
     */
    public String getLatestStreamKeyItemsData(String streamName, String keyName) throws IOException{
	String data = "";
	Object[] params = { streamName, keyName, false, 1, -1 };
	JSONObject json = invokeRPC(UUID.randomUUID().toString(), GET_STREAM_KEY_ITEMS, params);
	JSONArray result = (JSONArray) json.get("result");
	for (Object o : result){
	    JSONObject jsonLineItem = (JSONObject) o;
	    data = jsonLineItem.get("data").toString();
	}
	try{
	    if (result.toString().equals("[]"))
		return "error";
	    else
		return data;
	} catch (Exception e){
	    e.printStackTrace();
	    return "Error";
	}
    }
    /**
     * This method publishes the Data 'data' in the Stream 'streamName' against the key 'keyName'
     * @param streamName
     * @param keyName
     * @param data
     * @return
     * @throws IOException
     */
    public String publishToStreamForKey(String streamName, String keyName, byte[] data) throws IOException{
	//The Data has to be encoded in Hexadecimal form before it is stored in the stream on the blockchain
	String data1 = Hex.encodeHexString(data);
	Object[] params = { streamName, keyName, data1 };

	JSONObject json = invokeRPC(UUID.randomUUID().toString(), PUBLISH_ITEMS_FOR_KEY, params);

	if (json.get("result") == null)
	    return new String("Unsuccessful");
	else
	    return json.get("result").toString();

	}
}