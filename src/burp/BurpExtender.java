package burp;

import java.io.PrintWriter;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

public class BurpExtender implements IBurpExtender, IHttpListener, IProxyListener, IExtensionStateListener {
	private IBurpExtenderCallbacks callbacks;
	private PrintWriter stdout;
	private IExtensionHelpers BurpExtenderHelper;
	private final static String extName = "c2y2.org";

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		this.callbacks = callbacks;
		callbacks.setExtensionName(extName);
		stdout = new PrintWriter(callbacks.getStdout(), true);
		callbacks.registerProxyListener(this);
		callbacks.registerExtensionStateListener(this);
		callbacks.registerHttpListener(this);
		BurpExtenderHelper = callbacks.getHelpers();
	}

	@Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse message) {
		stdout.println((messageIsRequest ? "HTTP request to " : "HTTP response from ") + message.getHttpService()
				+ " [" + callbacks.getToolName(toolFlag) + "]");
		HashMap<String, String> checkParam = new HashMap<String, String>();
		if (messageIsRequest) {
			IHttpRequestResponse httpRequest = message;
			IRequestInfo reInfo = BurpExtenderHelper.analyzeRequest(httpRequest);
			List<IParameter> param = reInfo.getParameters();
			IParameter removeCsIParam = null;
			IParameter removeTsIParam = null;
			if (param != null && param.size() > 0) {
				Iterator<IParameter> iterator = param.iterator();
				while (iterator.hasNext()) {
					IParameter iParameter = iterator.next();
					stdout.println("name[" + iParameter.getName() + "]value[" + iParameter.getValue() + "]");
					if (iParameter.getName().equals("cs")) {
						removeCsIParam = iParameter;
					}
					if (iParameter.getName().equals("ts")) {
						removeTsIParam = iParameter;
					}
					if (iParameter.getName().equals("sid")) {
						Constants.sid = iParameter.getValue();
						stdout.println("request sid["+Constants.sid+"]");
					}
					checkParam.put(iParameter.getName(), iParameter.getValue());
				}
				checkParam.remove("ts");
				checkParam.remove("cs");
				String request = new String(httpRequest.getRequest());
				stdout.println("request[" + request + "]");
				String body = "";
				try {
					if (reInfo.getBodyOffset() > 0) {
						 body = request.substring(reInfo.getBodyOffset());
						if(body!=null && !body.isEmpty()){
							stdout.println("body[" + body + "]");
						}
					}
				} catch (Exception e) {
					stdout.println("error[" + e.getMessage() + "]");
				}
				if(!request.contains("login")){
					byte[] updateMessage = null;
					if (removeCsIParam != null) {
						updateMessage = BurpExtenderHelper.removeParameter(request.getBytes(), removeCsIParam);
					}
					if (removeTsIParam != null) {
						updateMessage = BurpExtenderHelper.removeParameter(updateMessage==null?request.getBytes():updateMessage, removeTsIParam);
					}
					IParameter addParams = null;
					String ts = (new Date().getTime() / 1000) + "";
					if (ts.contains(".")) {
						ts = ts.substring(0, ts.lastIndexOf("."));
					}
					if(updateMessage!=null){
						stdout.println("add param ts[" + ts + "]");
						addParams = BurpExtenderHelper.buildParameter("ts", ts, IParameter.PARAM_URL);
						updateMessage = BurpExtenderHelper.addParameter(updateMessage, addParams);
						if(!Constants.sid.isEmpty()){
							checkParam.put("ts", ts);
							checkParam.put("sid", Constants.sid);
							stdout.println("sid["+Constants.sid+"]");
							if(body!=null && !body.isEmpty()){
								checkParam.put("Data", body);
							}
							String cs = CheckUtil.check(checkParam);
							stdout.println("add param cs[" + cs + "]");
							addParams = BurpExtenderHelper.buildParameter("cs", cs, IParameter.PARAM_URL);
							updateMessage = BurpExtenderHelper.addParameter(updateMessage, addParams);
							httpRequest.setRequest(updateMessage);
						}
					}
				}
			}else{
				stdout.print("无参数");
			}
		}else{//response
			String responseBody = new String(message.getResponse());
			if(responseBody!=null){
				stdout.println("response body["+responseBody+"]");
				IResponseInfo resInfo = BurpExtenderHelper.analyzeResponse(message.getResponse());
				String reponseBody = responseBody.substring(resInfo.getBodyOffset());
				stdout.println("reponseBody_real["+reponseBody+"]");
				if(reponseBody!=null && !reponseBody.isEmpty()){
					try {
						if(reponseBody.contains("{") && reponseBody.contains("}")){
							reponseBody = reponseBody.replace("{", "").replace("}", "");
							String[] array =  reponseBody.split(",");
							for (String string : array) {
								if(string.contains("sid")){
									string = string.split(":")[1].replaceAll("\"", "");
									if(string!=null && !string.isEmpty()){
										stdout.println("update_sid["+Constants.sid+"]");
										Constants.sid=string;
									}
									stdout.println("response_sid["+Constants.sid+"]");
									break;
								}
							}
							
						}
					} catch (Exception e) {
						stdout.println("解析异常 非json body["+reponseBody+"]");
					}
				}
			}
		}
	}

	@Override
	public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
		stdout.println((messageIsRequest ? "Proxy request to " : "Proxy response from ")
				+ message.getMessageInfo().getHttpService());

	}

	@Override
	public void extensionUnloaded() {
		stdout.println(extName + "unloaded");
	}
}
