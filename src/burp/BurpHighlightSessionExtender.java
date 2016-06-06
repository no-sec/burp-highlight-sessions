package burp;

import java.io.PrintWriter;
import java.net.HttpCookie;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

public class BurpHighlightSessionExtender implements IBurpExtender, IProxyListener {

	private List<String> availableColors = new LinkedList<String>();
	private List<String> sessionCookieNames = new LinkedList<String>();
	private Map<String, String> session2ColorMap = new HashMap<String, String>();
	/**
	 * Object to print Strings to Burp Extender Console
	 */
	private PrintWriter stdout;
	private IExtensionHelpers helpers;

	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		// set our extension name
		callbacks.setExtensionName("Highlight Sessions");
		stdout = new PrintWriter(callbacks.getStdout(), true);

		initializeLists();

		this.helpers = callbacks.getHelpers();

		// register Proxy listener
		callbacks.registerProxyListener(this);
	}

	private void initializeLists() {
		// red, orange, yellow, green, cyan, blue, pink, magenta, gray,
		this.availableColors.add("red");
		this.availableColors.add("orange");
		this.availableColors.add("yellow");
		this.availableColors.add("green");
		this.availableColors.add("cyan");
		this.availableColors.add("blue");
		this.availableColors.add("pink");
		this.availableColors.add("magenta");
		this.availableColors.add("gray");

		// typical Session id names
		this.sessionCookieNames.add("jsessionid");
		this.sessionCookieNames.add("phpsessid");
		this.sessionCookieNames.add("sid");
		this.sessionCookieNames.add("aspsessionid");
		this.sessionCookieNames.add("sessionid");

	}

	//
	// implement IProxyListener
	//

	@Override
	public void processProxyMessage(boolean messageIsRequest,
			IInterceptedProxyMessage message) {
		if (messageIsRequest) {

			List<HttpCookie> cookies = this.getCookies(message);
			String cookieValue = this.getSessionCookieValue(cookies);
			if (null != cookieValue) {
				if (!this.session2ColorMap.containsKey(cookieValue
						.toLowerCase())) {
					int colorIndex = (this.session2ColorMap.size() + 1)
							% this.availableColors.size();
					this.session2ColorMap.put(cookieValue,
							this.availableColors.get(colorIndex));
				}
				message.getMessageInfo().setHighlight(
						this.session2ColorMap.get(cookieValue));
			}
		}
	}

	private List<HttpCookie> getCookies(IInterceptedProxyMessage message) {
		List<String> headers = this.helpers.analyzeRequest(
				message.getMessageInfo().getRequest()).getHeaders();
		for (Object header : headers) {
			if (((String) header).startsWith("Cookie:")) {
				String setCookie = "Set-" + header.toString();
				return HttpCookie.parse(setCookie);
			}
		}
		return new LinkedList<HttpCookie>();
	}

	private String getSessionCookieValue(List<HttpCookie> cookieList) {
		for (HttpCookie httpCookie : cookieList) {
			for (String sessionName : this.sessionCookieNames) {
				// TODO: handle Wildcards and/or RegEx in sessionName
				if (httpCookie.getName().toLowerCase().equals(sessionName.toLowerCase()))
					return httpCookie.getValue();
			}
		}
		return null;
	}

}