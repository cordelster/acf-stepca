<% local view, viewlibrary, page_info = ... %>
<% htmlviewfunctions = require("htmlviewfunctions") %>
<% html = require("acf.html") %>

<h1>Sign SSH Certificate</h1>

<% if view.has_ssh and view.has_ssh.value == "false" then %>
<div class="alert alert-danger">
	<h4><i class="icon-warning-sign"></i> SSH CA Not Initialized</h4>
	<p>
		This CA was not initialized with SSH support. SSH certificate signing is unavailable.<br>
		To enable it, re-initialize the CA with <strong>Enable SSH Certificate Authority</strong> checked.
	</p>
</div>
<% else %>

<% if view.error then %>
<div class="alert alert-danger">
	<strong>Error:</strong>
	<pre style="background:transparent;border:none;padding:0;margin-top:8px;white-space:pre-wrap;"><%= html.html_escape(view.error.value) %></pre>
</div>
<% if view.debug then %>
<div class="well well-sm"><strong>Debug:</strong><pre><%= html.html_escape(view.debug.value) %></pre></div>
<% end %>
<% end %>

<div class="alert alert-info">
	<strong>How this works:</strong>
	Users paste their SSH public key here. You sign it with the step-ca SSH CA.
	They save the returned certificate as <code>~/.ssh/id_*-cert.pub</code> alongside their private key.
	SSH will use it automatically on next login.
</div>

<form method="POST" action="<%= html.html_escape(page_info.script .. page_info.prefix .. page_info.controller .. "/dosshsign") %>">

	<fieldset>
		<legend>User's SSH Public Key</legend>
		<div class="form-group">
			<label for="ssh_pub_key"><%= html.html_escape(view.ssh_pub_key.label) %> *</label>
			<textarea id="ssh_pub_key" name="ssh_pub_key" class="form-control" rows="4"
				style="font-family:monospace;font-size:12px;"
				placeholder="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... user@host"><%= html.html_escape(view.ssh_pub_key.value) %></textarea>
			<small style="color:#777;"><%= html.html_escape(view.ssh_pub_key.descr) %></small>
		</div>
	</fieldset>

	<fieldset>
		<legend>Certificate Details</legend>

		<div class="form-group">
			<label for="identity"><%= html.html_escape(view.identity.label) %> *</label>
			<input type="text" id="identity" name="identity" class="form-control"
				value="<%= html.html_escape(view.identity.value) %>"
				placeholder="alice@company.com">
			<small style="color:#777;"><%= html.html_escape(view.identity.descr) %></small>
		</div>

		<div class="form-group">
			<label for="principals"><%= html.html_escape(view.principals.label) %> *</label>
			<input type="text" id="principals" name="principals" class="form-control"
				value="<%= html.html_escape(view.principals.value) %>"
				placeholder="alice,root">
			<small style="color:#777;"><%= html.html_escape(view.principals.descr) %></small>
		</div>

		<div class="form-group">
			<label for="validity"><%= html.html_escape(view.validity.label) %></label>
			<input type="text" id="validity" name="validity" class="form-control" style="width:auto;max-width:150px;"
				value="<%= html.html_escape(view.validity.value) %>"
				placeholder="24h">
			<small style="color:#777;"><%= html.html_escape(view.validity.descr) %></small>
		</div>

		<div class="form-group">
			<label for="cert_type"><%= html.html_escape(view.cert_type.label) %></label>
			<select id="cert_type" name="cert_type" style="width:auto;max-width:200px;">
				<% for _, opt in ipairs(view.cert_type.option) do %>
				<option value="<%= html.html_escape(opt) %>"<%= opt == view.cert_type.value and " selected" or "" %>><%= html.html_escape(opt:sub(1,1):upper()..opt:sub(2)) %></option>
				<% end %>
			</select>
			<small style="color:#777;display:block;margin-top:4px;"><%= html.html_escape(view.cert_type.descr) %></small>
		</div>
	</fieldset>

	<div class="form-group" style="margin-top:20px;">
		<button type="submit" class="btn btn-primary">
			<i class="icon-ok"></i> Sign SSH Certificate
		</button>
	</div>

</form>

<% end %>
