map = Map("tracker")

main = map:section(NamedSection, "main_sct", "tracker", "Tracker Configuration")
enabled = main:option(Flag, "enable", "Enable", "Enable program")

smtp_server = main:option(Value, "smtp_server", "SMTP server")
smtp_server.placeholder = "smtp://smtp.domain.com"
smtp_server.datatype = "url"
smtp_server.optional = false

smtp_port = main:option(Value, "smtp_port", "SMTP server port")
smtp_port.placeholder = "465"
smtp_port.datatype = "port"
smtp_port.optional = false

username = main:option(Value, "username", "Username")
username.placeholder = "Username"
username.datatype = "and(maxlength(64), string)"
username.optional = false

password = main:option(Value, "password", "Password")
password.placeholder = "Password"
password.datatype = "and(maxlength(64), string)"
password.password = true
password.optional = false

email = main:option(Value, "email", "Sender's Email address")
email.placeholder = "someone@domain.com"
email.datatype = "email"
email.optional = false

recipients = map:section(TypedSection, "recipient", "Recipients")
recipients.template = "cbi/tblsection"
recipients.delete_alert = true
recipients.alert_message = "Are you sure you want to delete this recipient?"
recipients.addremove = true
recipients.anonymous = true
recipients.sortable = true
recipients.template_addremove = "tracker/cbi_add_recipient"
recipients.novaluetext = "There are no recipients created yet"
recipients.defaults = {
    email = "",
    phone = "",
    validations = 0,
    changes = 0,
    errors = 0
}

email = recipients:option(DummyValue, "email", "Email address")
phone = recipients:option(DummyValue, "phone", "Phone number")
validations = recipients:option(DummyValue, "validations", "Validations")
function validations.cfgvalue(self, s) 
    local z = self.map:get(s, "validations")
    if z == "1" then
        return "yes"
    else
        return "no"
    end
end
changes = recipients:option(DummyValue, "changes", "Changes")
function changes.cfgvalue(self, s) 
    local z = self.map:get(s, "changes")
    if z == "1" then
        return "yes"
    else
        return "no"
    end
end
errors = recipients:option(DummyValue, "errors", "Errors")
function errors.cfgvalue(self, s) 
    local z = self.map:get(s, "errors")
    if z == "1" then
        return "yes"
    else
        return "no"
    end
end

function recipients.create(self, section)
    local email = self.map:formvalue("cbi." .. self.config .. "." .. self.sectiontype .. ".email")
    local phone = self.map:formvalue("cbi." .. self.config .. "." .. self.sectiontype .. ".phone")
    local validations = self.map:formvalue("cbi." .. self.config .. "." .. self.sectiontype .. ".validations")
    local changes = self.map:formvalue("cbi." .. self.config .. "." .. self.sectiontype .. ".changes")
    local errors = self.map:formvalue("cbi." .. self.config .. "." .. self.sectiontype .. ".errors")
    local created = TypedSection.create(self, section)

    self.map:set(created, "email", email)
    self.map:set(created, "phone", phone)
    self.map:set(created, "validations", validations)
    self.map:set(created, "changes", changes)
    self.map:set(created, "errors", errors)
    return created
end

return map