package burp;

public class TaboratorMessageEditorController implements IMessageEditorController {

    private IHttpService httpService;
    private byte[] request;
    private byte[] response;
    @Override
    public IHttpService getHttpService() {
        return httpService;
    }
    public void setHttpService(IHttpService httpService) {
        this.httpService = httpService;
    }

    @Override
    public byte[] getRequest() {
        return request;
    }
    public void setRequest(byte[] request) {
        this.request = request;
    }
    @Override
    public byte[] getResponse() {
        return response;
    }
    public void setResponse(byte[] response) {
        this.response = response;
    }
}
