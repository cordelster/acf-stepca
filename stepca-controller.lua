-- Alpine Configuration Framework (ACF) Controller for step-ca
-- Controller handles event dispatching and user interaction for PKI

local mymodule = {}

-- If CA not initialized, redirect to setup wizard
mymodule.default_action = "status"

-- Status/Dashboard Action
function mymodule.status(self)
    -- Check if CA is initialized, redirect to setup if not
    if not self.model.is_ca_initialized() then
        self.conf.action = "setup"
        return self:setup()
    end
    return self.model.get_status()
end

-- ===========================================================================
-- First-Time Setup Wizard
-- ===========================================================================

-- Show CA setup wizard
function mymodule.setup(self)
    return self.model.get_setup_form(self.clientdata)
end

-- Process CA initialization with password display
function mymodule.dosetup(self)
    return self.model.initialize_ca(self.clientdata)
end

-- ===========================================================================
-- Duration Limit (Claims) Management Actions
-- ===========================================================================

-- Get global claims
function mymodule.authorityclaims(self)
    return self.model.get_global_claims()
end

-- Save global claims
function mymodule.saveauthorityclaims(self)
    local result = self.model.save_global_claims(self.clientdata)
    self.conf.action = "authorityclaims"
    return result
end

-- Get provisioner specific claims
function mymodule.provisionerclaims(self)
    return self.model.get_provisioner_claims(self.clientdata)
end

-- Save provisioner specific claims
function mymodule.saveprovisionerclaims(self)
    local result = self.model.save_provisioner_claims(self.clientdata)
    self.conf.action = "provisionerclaims"
    return result
end

-- ===========================================================================
-- SSH Certificate Signing
-- ===========================================================================

-- SSH certificate signing form
function mymodule.sshsign(self)
    return self.model.get_ssh_sign_form(self.clientdata)
end

-- Process SSH certificate signing
function mymodule.dosshsign(self)
    return self.model.sign_ssh_cert(self.clientdata)
end

-- ===========================================================================
-- Certificate Management Actions
-- ===========================================================================

-- List all certificates
function mymodule.listcerts(self)
    return self.model.list_certificates(self.clientdata)
end


-- List certificates with expiration tracking
function mymodule.certexpiration(self)
    return self.model.list_certificates_with_expiration()
end

-- View certificate details
function mymodule.viewcert(self)
    return self.model.get_certificate_details(self.clientdata)
end

-- Export certificate (download cert/key/bundle)
function mymodule.exportcert(self)
    local result = self.model.export_certificate(self.clientdata)

    -- Check if we have content to download
    local has_content = (result.content ~= nil and result.content ~= "")
    local has_filename = (result.filename ~= nil and result.filename ~= "")

    -- If successful, send file directly and exit
    if has_content and has_filename then
        -- Send raw HTTP response
        io.stdout:write("HTTP/1.1 200 OK\r\n")
        io.stdout:write("Content-Type: application/octet-stream\r\n")
        io.stdout:write("Content-Disposition: attachment; filename=\"" .. tostring(result.filename) .. "\"\r\n")
        io.stdout:write("Content-Length: " .. tostring(string.len(result.content)) .. "\r\n")
        io.stdout:write("Connection: close\r\n")
        io.stdout:write("\r\n")
        io.stdout:write(result.content)
        io.stdout:flush()
        os.exit(0)
    end

    -- If we get here, return result to render error/debug view
    return result
end

-- Create new certificate form
function mymodule.createcert(self)
    return self.model.get_create_form(self.clientdata)
end

-- Process certificate creation
function mymodule.docreate(self)
    return self.model.create_certificate(self.clientdata)
end

-- Revoke certificate form
function mymodule.revokecert(self)
    return self.model.get_revoke_form(self.clientdata)
end

-- Process certificate revocation
function mymodule.dorevoke(self)
    return self.model.revoke_certificate(self.clientdata)
end

-- ===========================================================================
-- Provisioner Management Actions
-- ===========================================================================

-- List provisioners
function mymodule.provisioners(self)
    return self.model.list_provisioners()
end

-- Provisioner details view
function mymodule.provisionerdetails(self)
    return self.model.get_provisioner_details(self.clientdata)
end

-- Token generation form
function mymodule.gentoken(self)
    return self.model.get_token_form(self.clientdata)
end

-- Process token generation
function mymodule.dotoken(self)
    return self.model.generate_token(self.clientdata)
end

-- ===========================================================================
-- Template Management Actions
-- ===========================================================================

-- List template files
function mymodule.templates(self)
    return self.model.list_templates()
end

-- Add template form
function mymodule.addtemplate(self)
    return self.model.get_add_template_form(self.clientdata)
end

-- Edit template form
function mymodule.edittemplate(self)
    return self.model.get_template_details(self.clientdata)
end

-- Save template content
function mymodule.savetemplate(self)
    self.conf.action = "edittemplate"
    return self.model.save_template(self.clientdata)
end

-- Delete template file
function mymodule.deletetemplate(self)
    local result = self.model.delete_template(self.clientdata)
    self.conf.action = "templates"
    return self.model.list_templates()
end

-- ===========================================================================
-- Add provisioner form
function mymodule.addprovisioner(self)
    return self.model.get_add_provisioner_form(self.clientdata)
end

-- Save new provisioner
function mymodule.saveprovisioner(self)
    return self.model.add_provisioner(self.clientdata)
end

-- Delete provisioner
function mymodule.deleteprovisioner(self)
    return self.model.delete_provisioner(self.clientdata)
end

-- ===========================================================================
-- Configuration and Audit Actions
-- ===========================================================================

-- View CA hierarchy
function mymodule.cahierarchy(self)
    return self.model.get_ca_hierarchy()
end

-- Import certificate
function mymodule.importcert(self)
    return self.model.get_import_form(self.clientdata)
end

-- Process certificate import
function mymodule.doimport(self)
    return self.model.import_certificate(self.clientdata)
end

-- View CRL
function mymodule.viewcrl(self)
    return self.model.get_crl_info()
end

-- Refresh CRL
function mymodule.refreshcrl(self)
    return self.model.refresh_crl()
end

-- Client certificate management
function mymodule.clients(self)
    return self.model.list_clients()
end

-- Audit log viewer (PKI specific part)
function mymodule.auditlog(self)
    return self.model.get_audit_log(self.clientdata)
end

-- System configuration (PKI specific part)
function mymodule.config(self)
    return self.model.get_config()
end

-- Save configuration (PKI specific part)
function mymodule.saveconfig(self)
    return self.model.save_config(self.clientdata)
end

-- Start/stop/restart step-ca service (ACF standard pattern)
function mymodule.startstop(self)
    return self.handle_form(self, self.model.get_startstop, self.model.startstop_service, self.clientdata)
end

-- Restart step-ca service (used by config/provisioner pages)
function mymodule.restart(self)
    self.model.restart_service()
    self.conf.action = "status"
    return self.model.get_status()
end

return mymodule
