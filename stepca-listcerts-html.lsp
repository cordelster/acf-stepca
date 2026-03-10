<% local view, viewlibrary, page_info = ... %>
<% htmlviewfunctions = require("htmlviewfunctions") %>
<% html = require("acf.html") %>

<h1>Certificates</h1>

<form method="get" action="<%= html.html_escape(page_info.script .. page_info.prefix .. page_info.controller .. "/listcerts") %>" style="margin-bottom: 15px; white-space: nowrap;">
	<label for="filter" style="display:inline; margin-right:4px;">Type:</label>
	<select name="filter" id="filter" style="display:inline-block; width:auto; margin-right:15px;" onchange="this.form.submit()">
		<% local current_filter = view.filter and view.filter.value or "all" %>
		<% for _, opt in ipairs({"all", "infrastructure", "ephemeral"}) do %>
		<option value="<%= opt %>"<%= current_filter == opt and " selected" or "" %>><%= opt:sub(1,1):upper() .. opt:sub(2) %></option>
		<% end %>
	</select>
	<label for="expired_window" style="display:inline; margin-right:4px;">Expired:</label>
	<select name="expired_window" id="expired_window" style="display:inline-block; width:auto;" onchange="this.form.submit()">
		<%
		local current_window = view.expired_window and view.expired_window.value or "smart"
		local window_labels = {
			smart     = "Smart (auto)",
			["24h"]   = "Last 24 hours",
			["1w"]    = "Last 7 days",
			["all"]   = "All (troubleshooting)",
		}
		%>
		<% for _, opt in ipairs({"smart", "24h", "1w", "all"}) do %>
		<option value="<%= opt %>"<%= current_window == opt and " selected" or "" %>><%= window_labels[opt] %></option>
		<% end %>
	</select>
</form>

<div class="panel panel-default">
	<div class="panel-heading">
		<h3 class="panel-title">Certificates</h3>
	</div>
	<div class="panel-body">
		<% if view.count then %>
		<p>Total: <strong><%= html.html_escape(view.count.value) %></strong></p>
		<% end %>

		<% if view.certificates and #view.certificates > 0 then %>
		<table class="table table-striped table-hover">
			<thead>
				<tr>
					<th>Certificate Name</th>
					<th>Common Name</th>
					<th>Type</th>
					<th>Days Remaining</th>
					<th>Status</th>
					<th>Actions</th>
				</tr>
			</thead>
			<tbody>
				<% for i, cert in ipairs(view.certificates) do %>
				<%
					local row_class = ""
					if cert.color and cert.color.value then
						if cert.color.value == "red" then
							row_class = "danger"
						elseif cert.color.value == "yellow" then
							row_class = "warning"
						elseif cert.color.value == "green" or cert.color.value == "success" then
							row_class = "success"
						end
					end
				%>
				<tr class="<%= row_class %>">
					<td>
						<%= html.html_escape(cert.name.value) %>
						<% if cert.is_system_cert.value == "true" then %>
						<span class="label label-warning" style="margin-left: 5px;">SYSTEM</span>
						<% end %>
					</td>
					<td><%= html.html_escape(cert.subject.value) %></td>
					<td><%= html.html_escape(cert.cert_type.value) %></td>
					<td><strong><%= html.html_escape(cert.days_remaining.value) %></strong> days</td>
					<td>
						<%
							local emoji = ""
							local label_class = "default"
							if cert.status.value == "Revoked" then
								emoji = "🚫"
								label_class = "danger"
							elseif cert.status.value == "Expired" or cert.status.value == "Critical" then
								emoji = "🔴"
								label_class = "danger"
							elseif cert.status.value == "Warning" then
								emoji = "🟡"
								label_class = "warning"
							elseif cert.status.value == "Soon" then
								emoji = "🟡"
								label_class = "warning"
							elseif cert.status.value == "Valid" then
								emoji = "🟢"
								label_class = "success"
							end
						%>
						<%= emoji %> <span class="label label-<%= label_class %>">
							<%= html.html_escape(cert.status.value) %>
						</span>
					</td>
					<td>
						<a href="<%= html.html_escape(page_info.script .. page_info.prefix .. page_info.controller .. "/viewcert?cert_name=" .. cert.name.value) %>"
							class="btn btn-xs btn-info"
							title="View certificate details">
							<i class="icon-eye-open"></i> View
						</a>
						<a href="<%= html.html_escape(page_info.script .. page_info.prefix .. page_info.controller .. "/exportcert?cert_name=" .. cert.name.value .. "&type=cert") %>"
							class="btn btn-xs btn-success"
							title="Download certificate (.crt)">
							📄
						</a>
						<% if cert.is_system_cert.value ~= "true" then %>
						<a href="<%= html.html_escape(page_info.script .. page_info.prefix .. page_info.controller .. "/exportcert?cert_name=" .. cert.name.value .. "&type=key") %>"
							class="btn btn-xs btn-warning"
							title="Download private key (.key)">
							🔑
						</a>
						<a href="<%= html.html_escape(page_info.script .. page_info.prefix .. page_info.controller .. "/exportcert?cert_name=" .. cert.name.value .. "&type=bundle") %>"
							class="btn btn-xs btn-primary"
							title="Download bundle (cert + key)">
							📦
						</a>
						<% end %>
						<br>
						<% if cert.is_revoked.value == "true" then %>
						<span class="text-muted" style="font-size: 11px;">
							<i class="icon-ban-circle"></i> Already Revoked
						</span>
						<% elseif cert.is_system_cert.value == "true" then %>
						<span class="text-muted" style="font-size: 11px;">
							<i class="icon-lock"></i> Protected
						</span>
						<% else %>
						<a href="<%= html.html_escape(page_info.script .. page_info.prefix .. page_info.controller .. "/revokecert?cert_name=" .. cert.name.value .. "&serial=" .. cert.serial.value) %>"
							class="btn btn-xs btn-danger"
							onclick="return confirmRevoke('<%= html.html_escape(cert.name.value) %>');">
							<i class="icon-ban-circle"></i> Revoke
						</a>
						<% end %>
					</td>
				</tr>
				<% end %>
			</tbody>
		</table>

		<script>
		function confirmRevoke(certName) {
			// First confirmation: Warning dialog
			if (!confirm("WARNING: You are about to revoke certificate '" + certName + "'.\n\n" +
			             "This action is IRREVERSIBLE and will:\n" +
			             "- Immediately invalidate the certificate\n" +
			             "- Add it to the Certificate Revocation List (CRL)\n" +
			             "- Break any services using this certificate\n\n" +
			             "Do you want to continue?")) {
				return false;
			}

			// Second confirmation: Type the certificate name
			var userInput = prompt("To confirm revocation, please type the certificate name:\n\n" + certName);

			if (userInput === null) {
				// User clicked cancel
				return false;
			}

			if (userInput !== certName) {
				alert("Certificate name does not match. Revocation cancelled.");
				return false;
			}

			return true;
		}
		</script>
		<% else %>
		<div class="alert alert-info">
			No certificates found.
		</div>
		<% end %>
	</div>
</div>

<% if view.db_exec_time and view.db_exec_time.value ~= "" then %>
<div style="margin-top: 20px; padding-top: 10px; border-top: 1px solid #eee; text-align: right;">
	<small style="color: #999;">
		<i class="icon-time"></i> Database loaded via step-badger in <strong><%= html.html_escape(view.db_exec_time.value) %></strong> seconds
	</small>
</div>
<% end %>

<div class="form-group">
	<a href="<%= html.html_escape(page_info.script .. page_info.prefix .. page_info.controller .. "/createcert") %>"
		class="btn btn-primary"
		style="display: inline-block; padding: 6px 12px; font-size: 14px; color: #fff; background-color: #337ab7; border: 1px solid #2e6da4; border-radius: 4px; text-decoration: none;">
		<i class="icon-plus"></i> Create New Certificate
	</a>
</div>
