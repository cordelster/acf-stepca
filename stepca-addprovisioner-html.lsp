<% local view, viewlibrary, page_info = ... %>
<% htmlviewfunctions = require("htmlviewfunctions") %>
<% html = require("acf.html") %>

<h1>Add New Provisioner</h1>

<% if view.error then %>
<div class="alert alert-danger">
	<strong>Error:</strong>
	<pre style="background: transparent; border: none; padding: 0; margin-top: 10px; color: inherit; font-family: inherit; font-size: inherit; white-space: pre-wrap; overflow-wrap: break-word;"><%= html.html_escape(view.error.value) %></pre>
</div>
<div class="well well-sm">
	<strong>Debug info:</strong>
	<pre><%= html.html_escape(view.debug_cmd and view.debug_cmd.value or "No debug info captured") %></pre>
</div>
<% end %>

<% if view.success then %>
<div class="alert alert-success">
	<h4>Provisioner Added Successfully!</h4>
	<p><%= html.html_escape(view.success.value) %></p>

	<% if view.prov_password then %>
	<div style="margin-top: 20px; padding: 15px; background-color: #fff; border: 2px dashed #3c763d; border-radius: 4px;">
		<h5 style="color: #a94442; margin-top: 0;"><strong><i class="icon-warning-sign"></i> IMPORTANT: SECURITY KEY</strong></h5>
		<p>This is the password for your new JWK provisioner. <strong>Copy it now.</strong> It is only displayed once and cannot be retrieved through this web interface again.</p>
		<div class="input-group">
			<input type="text" class="form-control" id="copy-pass" value="<%= html.html_escape(view.prov_password.value) %>" readonly style="font-family: monospace; background-color: #eee;">
			<span class="input-group-btn">
				<button class="btn btn-default" type="button" onclick="copyToClipboard()">Copy</button>
			</span>
		</div>
	</div>

	<script>
	function copyToClipboard() {
		var copyText = document.getElementById("copy-pass");
		copyText.select();
		copyText.setSelectionRange(0, 99999);
		document.execCommand("copy");
		alert("Password copied to clipboard!");
	}
	</script>
	<% end %>

	<div style="margin-top: 15px; padding: 10px; border-top: 1px solid rgba(0,0,0,0.1);">
		<p><strong>Apply changes:</strong></p>
		<a href="<%= html.html_escape(page_info.script .. page_info.prefix .. page_info.controller .. "/restart") %>" class="btn btn-success btn-sm">
			<i class="icon-refresh"></i> <%= view.is_running and "Reload" or "Start" %> step-ca Now
		</a>
	</div>
	<% if view.output then %>
	<hr>
	<p><strong>Command Output:</strong></p>
	<pre><%= html.html_escape(view.output.value) %></pre>
	<% end %>
</div>
<div class="form-group">
	<a href="<%= html.html_escape(page_info.script .. page_info.prefix .. page_info.controller .. "/provisioners") %>"
		class="btn btn-primary">
		View All Provisioners
	</a>
</div>
<% else %>

<form method="POST" action="<%= html.html_escape(page_info.script .. page_info.prefix .. page_info.controller .. "/saveprovisioner") %>">

	<fieldset>
		<legend>Provisioner Configuration</legend>

		<% if view.prov_type then %>
		<div class="form-group" style="margin-bottom: 20px;">
			<label for="prov_type"><%= html.html_escape(view.prov_type.label) %> *</label>
			<select id="prov_type" name="prov_type" style="width: auto; max-width: 300px;" onchange="toggleFields()">
				<% for i, opt in ipairs(view.prov_type.option) do %>
				<option value="<%= html.html_escape(opt) %>" <% if opt == view.prov_type.value then %>selected<% end %>><%= html.html_escape(opt) %></option>
				<% end %>
			</select>
			<br><small style="color: #777; font-size: 85%;"><%= html.html_escape(view.prov_type.descr) %></small>
		</div>
		<% end %>

		<% if view.prov_name then %>
		<div class="form-group" style="margin-bottom: 20px;">
			<label for="prov_name"><%= html.html_escape(view.prov_name.label) %> *</label>
			<input type="text" id="prov_name" name="prov_name" value="<%= html.html_escape(view.prov_name.value) %>" size="50" placeholder="e.g., kanidm, letsencrypt" required>
			<br><small style="color: #777; font-size: 85%;"><%= html.html_escape(view.prov_name.descr) %></small>
		</div>
		<% end %>
	</fieldset>

	<fieldset id="template-fields">
		<legend>Certificate Templates</legend>
		<p><small style="color: #777;">Optional: Assign default templates to this provisioner.</small></p>

		<% if view.x509_template then %>
		<div class="form-group" style="margin-bottom: 20px;">
			<label for="x509_template"><%= html.html_escape(view.x509_template.label) %></label>
			<select id="x509_template" name="x509_template" style="width: auto; max-width: 400px;">
				<% for i, opt in ipairs(view.x509_template.option) do %>
				<option value="<%= html.html_escape(opt) %>" <% if opt == view.x509_template.value then %>selected<% end %>><%= html.html_escape(opt) %></option>
				<% end %>
			</select>
			<br><small style="color: #777; font-size: 85%;"><%= html.html_escape(view.x509_template.descr) %></small>
		</div>
		<% end %>

		<% if view.ssh_template then %>
		<div class="form-group" style="margin-bottom: 20px;">
			<label for="ssh_template"><%= html.html_escape(view.ssh_template.label) %></label>
			<select id="ssh_template" name="ssh_template" style="width: auto; max-width: 400px;">
				<% for i, opt in ipairs(view.ssh_template.option) do %>
				<option value="<%= html.html_escape(opt) %>" <% if opt == view.ssh_template.value then %>selected<% end %>><%= html.html_escape(opt) %></option>
				<% end %>
			</select>
			<br><small style="color: #777; font-size: 85%;"><%= html.html_escape(view.ssh_template.descr) %></small>
		</div>
		<% end %>
	</fieldset>

	<fieldset id="scep-fields">
		<legend>SCEP Configuration</legend>
		<p><small style="color: #777;">SCEP is commonly used for automated certificate enrollment on network switches, routers, and mobile devices.</small></p>

		<% if view.scep_challenge then %>
		<div class="form-group" style="margin-bottom: 20px;">
			<label for="scep_challenge"><%= html.html_escape(view.scep_challenge.label) %> *</label>
			<input type="password" id="scep_challenge" name="scep_challenge" class="form-control" placeholder="Shared secret for device enrollment">
			<small style="color: #777;"><%= html.html_escape(view.scep_challenge.descr) %></small>
		</div>
		<% end %>
	</fieldset>

	<fieldset id="oidc-fields">
		<legend>OIDC Configuration</legend>

		<% if view.client_id then %>
		<div class="form-group" style="margin-bottom: 20px;">
			<label for="client_id"><%= html.html_escape(view.client_id.label) %> *</label>
			<input type="text" id="client_id" name="client_id" value="<%= html.html_escape(view.client_id.value) %>" size="50" placeholder="OAuth2 Client ID">
			<br><small style="color: #777; font-size: 85%;"><%= html.html_escape(view.client_id.descr) %></small>
		</div>
		<% end %>

		<% if view.client_secret then %>
		<div class="form-group" style="margin-bottom: 20px;">
			<label for="client_secret"><%= html.html_escape(view.client_secret.label) %> *</label>
			<input type="password" id="client_secret" name="client_secret" value="<%= html.html_escape(view.client_secret.value) %>" size="50" placeholder="OAuth2 Client Secret">
			<br><small style="color: #777; font-size: 85%;"><%= html.html_escape(view.client_secret.descr) %></small>
		</div>
		<% end %>

		<% if view.config_endpoint then %>
		<div class="form-group" style="margin-bottom: 20px;">
			<label for="config_endpoint"><%= html.html_escape(view.config_endpoint.label) %> *</label>
			<input type="url" id="config_endpoint" name="config_endpoint" value="<%= html.html_escape(view.config_endpoint.value) %>" size="80" placeholder="https://your-kanidm.example.com/oauth2/openid/step-ca/.well-known/openid-configuration">
			<br><small style="color: #777; font-size: 85%;"><%= html.html_escape(view.config_endpoint.descr) %></small>
		</div>
		<% end %>

		<% if view.listen_address then %>
		<div class="form-group" style="margin-bottom: 20px;">
			<label for="listen_address"><%= html.html_escape(view.listen_address.label) %></label>
			<input type="text" id="listen_address" name="listen_address" value="<%= html.html_escape(view.listen_address.value) %>" size="20" placeholder=":10000">
			<br><small style="color: #777; font-size: 85%;"><%= html.html_escape(view.listen_address.descr) %></small>
		</div>
		<% end %>
	</fieldset>

	<fieldset id="oidc-help" style="margin-top: 30px;">
		<legend>Getting Kanidm OAuth2 Credentials</legend>
		<p>To get the OAuth2 credentials from Kanidm, run these commands on your Kanidm server:</p>
		<pre># Create OAuth2 client
kanidm system oauth2 create step-ca "Step-CA Certificate Authority" https://YOUR-CA-SERVER:10000

# Update scope mapping
kanidm system oauth2 update-scope-map step-ca YOUR_GROUP email openid

# Enable PKCE (recommended for security)
kanidm system oauth2 enable-pkce step-ca

# Get the client secret
kanidm system oauth2 show-basic-secret step-ca</pre>

		<p>
			<small style="color: #777; font-size: 85%;">
				The configuration endpoint URL format for Kanidm is:<br>
				<code>https://YOUR-KANIDM-SERVER/oauth2/openid/step-ca/.well-known/openid-configuration</code>
			</small>
		</p>
	</fieldset>

	<fieldset id="acme-help" style="margin-top: 30px; display: none;">
		<legend>ACME Provisioner Information</legend>
		<p><strong>ACME (Automatic Certificate Management Environment)</strong> is the protocol used by Let's Encrypt and other public CAs.</p>
		<ul>
			<li>No additional configuration required</li>
			<li>Clients use ACME protocol to request certificates automatically</li>
			<li>Supports challenge types: http-01, dns-01, tls-alpn-01</li>
			<li>Ideal for automated certificate renewal (certbot, acme.sh, etc.)</li>
		</ul>
	</fieldset>

	<fieldset id="jwk-help" style="margin-top: 30px; display: none;">
		<legend>JWK Provisioner Information</legend>
		<p><strong>JWK (JSON Web Key)</strong> is a simple key-based provisioner for manual certificate issuance.</p>
		<ul>
			<li>No additional configuration required - keys are auto-generated</li>
			<li>Use <code>step ca token</code> to generate tokens for certificate requests</li>
			<li>Ideal for manual certificate issuance and testing</li>
			<li>Default provisioner type for new CAs</li>
		</ul>
		<p><small style="color: #777;">After adding this provisioner, use: <code>step ca token &lt;common-name&gt;</code></small></p>
	</fieldset>

	<fieldset id="sshpop-help" style="margin-top: 30px; display: none;">
		<legend>SSHPOP Provisioner Information</legend>
		<% if view.has_ssh and view.has_ssh.value == "false" then %>
		<div class="alert alert-danger">
			<strong>SSH CA not initialized.</strong> SSHPOP will not function.<br>
			The CA must be re-initialized with <em>Enable SSH Certificate Authority</em> checked.
			SSH CA keys (<code>ssh_user_ca_key</code>, <code>ssh_host_ca_key</code>) are generated
			by <code>step ca init --ssh</code> and cannot be added after the fact.
		</div>
		<% else %>
		<div class="alert alert-info">
			<strong>SSH CA detected.</strong> SSHPOP is available.
		</div>
		<% end %>
		<p><strong>SSHPOP (SSH Proof of Possession)</strong> allows users to exchange an SSH certificate for an X.509 certificate.</p>
		<p><strong>Prerequisites:</strong></p>
		<ol>
			<li>CA initialized with SSH support (<code>step ca init --ssh</code>)</li>
			<li>User has an SSH <em>certificate</em> (not just a key) signed by the step-ca SSH user CA:<br>
				<code>step ssh certificate user@example.com ~/.ssh/id_ed25519.pub</code></li>
		</ol>
		<p><strong>Client certificate request:</strong></p>
		<pre>step ca certificate &lt;cn&gt; cert.crt cert.key \
  --provisioner &lt;sshpop-name&gt; \
  --ssh-pop-cert ~/.ssh/id_ed25519-cert.pub \
  --ssh-pop-key ~/.ssh/id_ed25519</pre>
	</fieldset>

	<div class="form-group" style="margin-top: 30px;">
		<button type="submit" class="btn btn-primary">
			<i class="icon-ok"></i> Add Provisioner
		</button>
		<button type="button" class="btn btn-default" onclick="window.location.href='<%= html.html_escape(page_info.script .. page_info.prefix .. page_info.controller .. "/provisioners") %>'">
			<i class="icon-remove"></i> Cancel
		</button>
	</div>

<fieldset id="scep-help" style="margin-top: 30px; display: none;">
	<legend>SCEP Provisioner Information</legend>
	<p><strong>SCEP (Simple Certificate Enrollment Protocol)</strong> is the industry standard for network equipment.</p>
	<ul>
		<li>Supported by Cisco, Juniper, Aruba, Ubiquiti, and most managed switches</li>
		<li>Uses a shared secret (Challenge) for initial device authentication</li>
		<li>Ideal for routers, switches, and IoT devices that don't support modern OAuth/OIDC</li>
		<li>Enables fully automated zero-touch deployment for networking gear</li>
	</ul>
	<p><small style="color: #777;">Point your switch to: <code>https://YOUR-CA-SERVER/scep/&lt;provisioner-name&gt;</code></small></p>
</fieldset>

<div class="form-group" style="margin-top: 30px;">
...
<script>
function toggleFields() {
var provType = document.getElementById('prov_type').value;
var oidcFields = document.getElementById('oidc-fields');
var scepFields = document.getElementById('scep-fields');
var oidcHelp = document.getElementById('oidc-help');
var acmeHelp = document.getElementById('acme-help');
var jwkHelp = document.getElementById('jwk-help');
var scepHelp = document.getElementById('scep-help');
var sshpopHelp = document.getElementById('sshpop-help');

// Hide all sections first
if (oidcFields) oidcFields.style.display = 'none';
if (scepFields) scepFields.style.display = 'none';
if (oidcHelp) oidcHelp.style.display = 'none';
if (acmeHelp) acmeHelp.style.display = 'none';
if (jwkHelp) jwkHelp.style.display = 'none';
if (scepHelp) scepHelp.style.display = 'none';
if (sshpopHelp) sshpopHelp.style.display = 'none';

// Show relevant sections
if (provType === 'OIDC') {
	if (oidcFields) oidcFields.style.display = 'block';
	if (oidcHelp) oidcHelp.style.display = 'block';
} else if (provType === 'ACME') {
	if (acmeHelp) acmeHelp.style.display = 'block';
} else if (provType === 'JWK') {
	if (jwkHelp) jwkHelp.style.display = 'block';
} else if (provType === 'SCEP') {
	if (scepFields) scepFields.style.display = 'block';
	if (scepHelp) scepHelp.style.display = 'block';
} else if (provType === 'SSHPOP') {
	if (sshpopHelp) sshpopHelp.style.display = 'block';
}
}

// Initialize on page load
toggleFields();
</script>

<% end %>
