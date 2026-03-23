<% local view, viewlibrary, page_info = ... %>
<% htmlviewfunctions = require("htmlviewfunctions") %>
<% html = require("acf.html") %>

<h1>PKI Configuration</h1>

<% if view.success then %>
<div class="alert alert-success">
	<h4>Configuration Saved Successfully!</h4>
	<p><%= html.html_escape(view.success.value) %></p>
	<% if view.restart_required then %>
	<div style="margin-top: 15px; padding: 10px; border-top: 1px solid rgba(0,0,0,0.1);">
		<p><strong>Note:</strong> Network changes require a service reload to take effect.</p>
		<a href="<%= html.html_escape(page_info.script .. page_info.prefix .. page_info.controller .. "/restart") %>" class="btn btn-success btn-sm">
			<i class="icon-refresh"></i> Reload step-ca Now
		</a>
	</div>
	<% end %>
</div>
<% elseif view.error then %>
<div class="alert alert-danger">
	<strong>Error:</strong> <%= html.html_escape(view.error.value) %>
</div>
<% end %>

<div class="panel panel-default">
	<div class="panel-heading">
		<h3 class="panel-title">Application Settings</h3>
	</div>
	<div class="panel-body">
		<form method="POST" action="<%= html.html_escape(page_info.script .. page_info.prefix .. page_info.controller .. "/saveconfig") %>" class="form-horizontal">

			<!-- Network Configuration (ca.json) -->
			<h4 class="text-info">🌐 Network Configuration</h4>
			<p class="text-muted" style="margin-bottom: 20px;">
				<small>Core server settings stored in ca.json. Changes require a service reload.</small>
			</p>

			<% if view.ca_dns then %>
			<div class="form-group">
				<label class="col-sm-3 control-label"><%= html.html_escape(view.ca_dns.label) %></label>
				<div class="col-sm-9">
					<input type="text"
						name="ca_dns"
						class="form-control"
						value="<%= html.html_escape(view.ca_dns.value) %>"
						placeholder="e.g., pki.example.com">
					<p class="help-block"><%= html.html_escape(view.ca_dns.descr) %></p>
				</div>
			</div>
			<% end %>

			<% if view.ca_address then %>
			<div class="form-group">
				<label class="col-sm-3 control-label"><%= html.html_escape(view.ca_address.label) %></label>
				<div class="col-sm-9">
					<input type="text"
						name="ca_address"
						class="form-control"
						value="<%= html.html_escape(view.ca_address.value) %>"
						placeholder="e.g., :443 or 0.0.0.0:443">
					<p class="help-block"><%= html.html_escape(view.ca_address.descr) %></p>
				</div>
			</div>
			<% end %>

			<hr style="margin: 30px 0;">

			<!-- Certificate Expiration Thresholds -->
			<h4 class="text-primary">🏛️ Expiration Thresholds</h4>
			<p class="text-muted" style="margin-bottom: 20px;">
				<small>All certificates use the ACME 1/3-lifetime model — status is based on % of lifetime remaining, not a fixed number of days. Default: 🔵 33% (renewal window opens) → 🟡 16% → 🔴 8% (critical).</small>
			</p>

			<div class="form-group">
				<label class="col-sm-3 control-label">Thresholds (% lifetime remaining)</label>
				<div class="col-sm-9">
					<div class="row">
						<div class="col-xs-4">
							<div class="input-group">
								<span class="input-group-addon" title="Notice — renewal window opens">🔵</span>
								<input type="number" name="notice_percent" class="form-control" value="<%= html.html_escape(view.notice_percent.value) %>" min="1" max="100">
								<span class="input-group-addon">%</span>
							</div>
						</div>
						<div class="col-xs-4">
							<div class="input-group">
								<span class="input-group-addon" title="Warning">🟡</span>
								<input type="number" name="warning_percent" class="form-control" value="<%= html.html_escape(view.warning_percent.value) %>" min="1" max="100">
								<span class="input-group-addon">%</span>
							</div>
						</div>
						<div class="col-xs-4">
							<div class="input-group">
								<span class="input-group-addon" title="Critical">🔴</span>
								<input type="number" name="critical_percent" class="form-control" value="<%= html.html_escape(view.critical_percent.value) %>" min="1" max="100">
								<span class="input-group-addon">%</span>
							</div>
						</div>
					</div>
					<p class="help-block"><%= html.html_escape(view.notice_percent.descr) %></p>
				</div>
			</div>

			<div class="form-group" style="margin-top: 20px;">
				<div class="col-sm-offset-3 col-sm-9">
					<button type="submit" class="btn btn-primary">
						<i class="icon-ok"></i> Save All Settings
					</button>
				</div>
			</div>
		</form>
	</div>
</div>

<div class="panel panel-info">
	<div class="panel-heading">
		<h3 class="panel-title">Global Authority Policies</h3>
	</div>
	<div class="panel-body">
		<p>Define absolute maximum duration limits for all certificates issued by this CA.</p>
		<div style="margin-top: 15px;">
			<a href="<%= html.html_escape(page_info.script .. page_info.prefix .. page_info.controller .. "/authorityclaims") %>" 
			   class="btn btn-primary"
			   style="display: inline-block; padding: 6px 12px; font-size: 14px; color: #fff; background-color: #337ab7; border: 1px solid #2e6da4; border-radius: 4px; text-decoration: none;">
				<i class="icon-time"></i> Manage Global CA Limits
			</a>
		</div>
	</div>
</div>
