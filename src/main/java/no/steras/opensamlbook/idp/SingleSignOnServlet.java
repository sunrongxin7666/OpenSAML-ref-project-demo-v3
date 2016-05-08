package no.steras.opensamlbook.idp;

import no.steras.opensamlbook.sp.SPConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.Writer;

public class SingleSignOnServlet extends HttpServlet {
    private static Logger logger = LoggerFactory.getLogger(SingleSignOnServlet.class);

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        logger.info("AuthnRequest recieved");
        Writer w = resp.getWriter();
        resp.setContentType("text/html");
        w.append("<html>" + "<head></head>" + "<body><h1>You are now at IDP, click the button to authenticate</h1> <form method=\"POST\">"
                + "<input type=\"submit\" value=\"Authenticate\"/>" + "</form>" + "</body>" + "</html>");
    }

    @Override
    protected void doPost(final HttpServletRequest req, final HttpServletResponse resp) throws ServletException, IOException {
        resp.sendRedirect(SPConstants.ASSERTION_CONSUMER_SERVICE + "?SAMLart=AAQAAMFbLinlXaCM%2BFIxiDwGOLAy2T71gbpO7ZhNzAgEANlB90ECfpNEVLg%3D");
    }


}
