module ApplicationHelper


  def devise_mapping
    request.env["devise.mapping"] = Devise.mappings[:user]
    @devise_mapping ||= request.env["devise.mapping"]
  end

  def resource_name
    devise_mapping.name
  end

  def resource
    instance_variable_get(:"@#{resource_name}")
  end

  def resource=(new_resource)
    instance_variable_set(:"@#{resource_name}", new_resource)
  end

  BOOTSTRAP_ALERT_CLASS = {
    "error" => "danger",
    "warning" => "warning",
    "notice" => "success",
    "alert" => "warning"
  }

  def display_flash
    return if flash.empty?
    flash.map do |key, value|
      content_tag :div, value, class: "alert alert-#{BOOTSTRAP_ALERT_CLASS[key] || "info"}"
    end.join("").html_safe
  end

end
