package com.nicico.cost.jsonweb.service.enums;

import com.nicico.cost.framework.utility.view.Message;

public enum JsonWebException implements Message {

    JWT_TOKEN_EXPIRED {
        @Override
        public String key() {
            return this.name();
        }
    },

    JWT_TOKEN_INVALID {
        @Override
        public String key() {
            return this.name();
        }
    }
}
