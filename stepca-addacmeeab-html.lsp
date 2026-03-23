<% local view, viewlibrary, page_info = ... %>
<% html = require("acf.html") %>

<h1>New EAB Key<% if view.acme_prov then %> &mdash; <%= html.html_escape(view.acme_prov.value) %><% end %></h1>

<% if view.error then %>
<div class="alert alert-danger">
	<strong>Error:</strong>
	<pre style="background: transparent; border: none; padding: 0; margin-top: 8px; color: inherit; white-space: pre-wrap;"><%= html.html_escape(view.error.value) %></pre>
</div>
<% else %>

<div class="alert alert-success">
	<strong>EAB Key Generated Successfully!</strong>
</div>

<div class="panel panel-danger">
	<div class="panel-heading">
		<h3 class="panel-title"><i class="icon-warning-sign"></i> Save These Credentials Now</h3>
	</div>
	<div class="panel-body">
		<p><strong>The HMAC key is shown once and cannot be retrieved again.</strong> Copy both values before leaving this page.</p>

		<% if view.eab_key_id and view.eab_key_id.value ~= "" then %>
		<div class="form-group">
			<label>Key ID (not secret &mdash; share with ACME client)</label>
			<div class="input-group" style="max-width: 600px;">
				<input type="text" id="eab-key-id" class="form-control" value="<%= html.html_escape(view.eab_key_id.value) %>" readonly style="font-family: monospace;">
				<span class="input-group-btn"><button class="btn btn-default" type="button" onclick="copyField('eab-key-id')">Copy</button></span>
			</div>
		</div>
		<div class="form-group">
			<label>HMAC Key (secret &mdash; give to ACME client, never log)</label>
			<div class="input-group" style="max-width: 600px;">
				<input type="text" id="eab-hmac" class="form-control" value="<%= html.html_escape(view.eab_hmac_key.value) %>" readonly style="font-family: monospace; background-color: #fff3cd;">
				<span class="input-group-btn"><button class="btn btn-default" type="button" onclick="copyField('eab-hmac')">Copy</button></span>
			</div>
		</div>
		<% else %>
		<div class="form-group">
			<label>Raw Output</label>
			<textarea class="form-control" rows="8" readonly style="font-family: monospace;"><%= html.html_escape(view.eab_output and view.eab_output.value or "") %></textarea>
		</div>
		<% end %>
	</div>
</div>

<% if view.directory_url and view.directory_url.value ~= "" then %>
<div class="panel panel-default">
	<div class="panel-heading">
		<h3 class="panel-title">Client Configuration</h3>
	</div>
	<div class="panel-body">
		<p>Configure your ACME client with these values:</p>
		<table class="table table-condensed" style="max-width: 700px;">
			<tr><td><strong>Directory URL</strong></td><td><code><%= html.html_escape(view.directory_url.value) %></code></td></tr>
			<% if view.eab_key_id and view.eab_key_id.value ~= "" then %>
			<tr><td><strong>EAB Key ID</strong></td><td><code><%= html.html_escape(view.eab_key_id.value) %></code></td></tr>
			<tr><td><strong>EAB HMAC Key</strong></td><td><code><em>(copied above)</em></code></td></tr>
			<% end %>
		</table>

		<p><strong>Example &mdash; certbot:</strong></p>
		<pre style="background:#f8f8f8; border:1px solid #ddd; padding:10px; border-radius:4px;">certbot certonly --standalone \
  --server <%= html.html_escape(view.directory_url.value) %> \
  --eab-kid <%= html.html_escape(view.eab_key_id and view.eab_key_id.value or "KEY_ID") %> \
  --eab-hmac-key HMAC_KEY \
  -d myhost.local</pre>

		<p><strong>Example &mdash; acme.sh:</strong></p>
		<pre style="background:#f8f8f8; border:1px solid #ddd; padding:10px; border-radius:4px;">acme.sh --register-account \
  --server <%= html.html_escape(view.directory_url.value) %> \
  --eab-kid <%= html.html_escape(view.eab_key_id and view.eab_key_id.value or "KEY_ID") %> \
  --eab-hmac-key HMAC_KEY</pre>
	</div>
</div>
<% end %>

<% end %>

<div class="form-group" style="margin-top: 20px;">
	<a href="<%= html.html_escape(page_info.script .. page_info.prefix .. page_info.controller .. "/acmeeab" .. (view.acme_prov and ("?acme_prov=" .. view.acme_prov.value) or "")) %>"
		class="btn btn-default">Back to EAB Management</a>
	<a href="<%= html.html_escape(page_info.script .. page_info.prefix .. page_info.controller .. "/provisioners") %>"
		class="btn btn-default" style="margin-left: 5px;">Back to Provisioners</a>
</div>

<script>
function copyField(id) {
	var el = document.getElementById(id);
	el.select(); el.setSelectionRange(0, 99999);
	document.execCommand("copy");
	alert("Copied to clipboard!");
}
</script>
