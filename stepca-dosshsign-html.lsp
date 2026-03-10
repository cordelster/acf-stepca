<% local view, viewlibrary, page_info = ... %>
<% htmlviewfunctions = require("htmlviewfunctions") %>
<% html = require("acf.html") %>

<h1>SSH Certificate Signing Result</h1>

<% if view.error then %>
<div class="alert alert-danger">
	<h4>Signing Failed</h4>
	<pre style="background:transparent;border:none;padding:0;white-space:pre-wrap;"><%= html.html_escape(view.error.value) %></pre>
</div>
<% if view.debug then %>
<div class="well well-sm"><strong>Debug output:</strong><pre><%= html.html_escape(view.debug.value) %></pre></div>
<% end %>
<div class="form-group" style="margin-top:15px;">
	<a href="<%= html.html_escape(page_info.script .. page_info.prefix .. page_info.controller .. "/sshsign") %>"
		class="btn btn-default"><i class="icon-arrow-left"></i> Back</a>
</div>

<% elseif view.success then %>

<div class="alert alert-success">
	<h4><i class="icon-ok"></i> <%= html.html_escape(view.success.value) %></h4>
	<% if view.identity then %><p><strong>Identity:</strong> <%= html.html_escape(view.identity.value) %></p><% end %>
	<% if view.principals then %><p><strong>Principals:</strong> <%= html.html_escape(view.principals.value) %></p><% end %>
	<% if view.validity then %><p><strong>Valid for:</strong> <%= html.html_escape(view.validity.value) %></p><% end %>
	<% if view.cert_type then %><p><strong>Type:</strong> <%= html.html_escape(view.cert_type.value) %> certificate</p><% end %>
</div>

<% if view.cert_content then %>
<div class="panel panel-default">
	<div class="panel-heading">
		<h3 class="panel-title">
			Signed Certificate
			<% if view.filename then %>
			<small style="font-weight:normal;"> — <%= html.html_escape(view.cert_content.descr) %></small>
			<% end %>
		</h3>
	</div>
	<div class="panel-body">
		<textarea id="cert-output" class="form-control" rows="4" readonly
			style="font-family:monospace;font-size:12px;"><%= html.html_escape(view.cert_content.value) %></textarea>

		<div style="margin-top:12px;">
			<button class="btn btn-default btn-sm" onclick="copyCert()">
				<i class="icon-copy"></i> Copy to Clipboard
			</button>
			<% if view.filename then %>
			<button class="btn btn-primary btn-sm" style="margin-left:8px;" onclick="downloadCert()">
				<i class="icon-download-alt"></i> Download <%= html.html_escape(view.filename.value) %>
			</button>
			<% end %>
		</div>

		<div class="alert alert-warning" style="margin-top:20px;">
			<strong>Instructions for the user:</strong>
			<ol style="margin-bottom:0;">
				<% if view.filename then %>
				<li>Save this certificate as <code>~/.ssh/<%= html.html_escape(view.filename.value) %></code></li>
				<% else %>
				<li>Save this as <code>id_*-cert.pub</code> in <code>~/.ssh/</code></li>
				<% end %>
				<li>The file must sit next to the corresponding private key in <code>~/.ssh/</code></li>
				<li>SSH will use it automatically — no further config needed</li>
				<li>Verify with: <code>ssh-keygen -L -f ~/.ssh/<%= view.filename and html.html_escape(view.filename.value) or "id_*-cert.pub" %></code></li>
			</ol>
		</div>
	</div>
</div>

<script>
function copyCert() {
	var ta = document.getElementById('cert-output');
	ta.select();
	ta.setSelectionRange(0, 99999);
	document.execCommand('copy');
	alert('Certificate copied to clipboard!');
}
<% if view.cert_content and view.filename then %>
function downloadCert() {
	var content = <%= string.format("%q", view.cert_content.value) %>;
	var filename = '<%= html.html_escape(view.filename.value) %>';
	var blob = new Blob([content + '\n'], {type: 'text/plain'});
	var url = URL.createObjectURL(blob);
	var a = document.createElement('a');
	a.href = url;
	a.download = filename;
	document.body.appendChild(a);
	a.click();
	document.body.removeChild(a);
	URL.revokeObjectURL(url);
}
<% end %>
</script>

<% end %>

<div class="form-group" style="margin-top:15px;">
	<a href="<%= html.html_escape(page_info.script .. page_info.prefix .. page_info.controller .. "/sshsign") %>"
		class="btn btn-default"><i class="icon-plus"></i> Sign Another Certificate</a>
</div>

<% end %>
