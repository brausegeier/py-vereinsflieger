################################################################################
# py-vereinsflieger/mail_sender.py
#
# Copyright Alexander Bleitner, 2021.
#
# License: GPL-3.0-or-later
################################################################################


import smtplib
from email.message  import EmailMessage
from sys            import _getframe as s_frame


class MailSender():
    ####################
    # public interface #
    ####################

    def __init__(self, hostname = None, port = 0, debug = 0):
        self._debug         = debug
        self._hostname      = hostname
        self._port          = port
        self._mail_user     = None
        self._mail_pwd      = None
        self._mail_bcc      = None
        self._mail_reply_to = None


    def set_server(self, hostname, port):
        self._hostname  = hostname
        self._port      = port


    def add_bcc_address(self, bcc_addr):
        if self._mail_bcc is not None:
            self._mail_bcc  = self._mail_bcc + ", " + bcc_addr
        else:
            self._mail_bcc  = bcc_addr


    def add_reply_to_address(self, reply_to_addr):
        if self._mail_reply_to is not None:
            self._mail_reply_to = self._mail_reply_to + ", " + reply_to_addr
        else:
            self._mail_reply_to = reply_to_addr


    def set_credentials(self, user_id, pwd):
        self._mail_user = user_id
        self._mail_pwd  = pwd


    def set_banking_data(self, bank_account_holder, iban, bic, bank_name):
        self._bank_holder = bank_account_holder
        self._bank_iban   = iban
        self._bank_bic    = bic
        self._bank_name   = bank_name


    def send_voucher_mail(self, voucher):
        msg = self._compose_message(voucher) 

        server = smtplib.SMTP_SSL(self._hostname, self._port)
        server.login(self._mail_user, self._mail_pwd)
        server.send_message(msg)
        server.quit()

        return 0



    #############
    # internals #
    #############

    #######
    def _compose_message(self, voucher):
    #######
        # convert type/amount into human readable form
        if voucher["type"] == "SF":
            voucher_type = "Segelflug"
            info_tmg = ""
        elif voucher["type"] == "TMG":
            # convert euros with ',' separator to value with '.' separator
            voucher_euro = int(voucher["amount"].split(",")[0])
            voucher_euro = float(voucher_euro) + float(int(voucher["amount"].split(",")[1]) / 100.0)
            voucher_minutes = 60.0 * voucher_euro / 110.0
            voucher_minutes = int(round(voucher_minutes, 0))
            voucher_type = ("%d minütigen Motorsegler" % voucher_minutes)
            info_tmg = "\nUm einen Termin für den Flug zu vereinbaren, antworten Sie bitte auf diese Email an <mailto:mitfliegen@brausegeier.de>.\n"
        else:
            voucher_type = "!Fehler!"
            voucher_amount = 0
            info_tmg = ""

        # create email
        msg = EmailMessage()
        msg["Subject"]  = "Brausegeier.de Gutscheinbestellung"
        msg["From"]     = "mitfliegen@brausegeier.de"
        msg["To"]       = voucher["buyer_email"]
        if self._mail_bcc is not None:
            msg["Bcc"] = self._mail_bcc
        if self._mail_reply_to is not None:
            msg.add_header('reply-to', self._mail_reply_to)
        msg_content = ('''Hallo %s %s,

Sie haben einen %s Gutschein für %s %s bestellt. Bitte überweisen Sie den Betrag von %s Euro auf das folgende Konto um den Gutschein zu aktivieren:

Inhaber: %s
IBAN: %s
BIC: %s
Bank: %s
Verwendungszweck: %s, %s

Sobald wir den Geldeingang bei uns verbuchen, gilt die Gutscheinnummer zusammen mit dem Ausweis des Begünstigten als Zahlungsnachweis und kann gegen den
entsprechenden Flug vor Ort eingelöst werden. Bitte beachten Sie, dass Gutscheine drei Jahre lang gültig sind.
%s
Falls Sie weitere Fragen zur Rechnung haben, antworten Sie bitte auf diese Email an unseren Schatzmeister Jan Schandl <mailto:%s>.

Selbstverständlich dürfen Sie die Gutscheinnummer auf einem selbst gestalteten Gutschein an die begünstigte Person verschenken.

Viele Grüße
Alexander Bleitner

Mitglied des erweiterten Vorstandes
<mailto:mitfliegen@brausegeier.de>
————————————————
Breisgauverein für Segelflug e. V. 
Postfach 6221
79038 Freiburg
————————————————
www.brausegeier.de <http://www.brausegeier.de/>

Unser Newsletter auto-Cumulus kann hier
<https://brausegeier.de/newsletter-autocumulus/> abonniert
werden.

Instagram: Breisgauverein_Segelflug
<https://instagram.com/breisgauverein_segelflug>''' % (
            voucher["buyer_firstname"], voucher["buyer_lastname"], voucher_type, voucher["guest_firstname"], voucher["guest_lastname"], voucher["amount"], 
            self._bank_holder, self._bank_iban, self._bank_bic, self._bank_name, voucher["id"], voucher["buyer_lastname"], info_tmg, self._mail_reply_to))
        msg.set_content(msg_content)

        # if present, add invoice as attachment
        if "invoice_pdf" in voucher.keys() and voucher["invoice_pdf"] is not None:
            if "invoice_id" in voucher.keys() and voucher["invoice_id"] is not None:
                invoice_name = "Rechnung_"+str(voucher["invoice_id"])+".pdf"
            else:
                invoice_name = "Rechnung.pdf"
            msg.add_attachment(voucher["invoice_pdf"], maintype='application', subtype='pdf', filename=invoice_name)

        return msg

